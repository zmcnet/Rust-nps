#!/usr/bin/env python3
"""Dump the import table (and delay-import table) of PE/COFF binaries.

Pure Python standard library, no third-party dependencies. Works with any
Python 3.7+; run it with ``python -I`` to keep the working directory out of
``sys.path`` when inspecting untrusted binaries.

Usage:
    python -I scripts/pe_imports.py target/release/npsd.exe
    python -I scripts/pe_imports.py --json a.exe b.exe
    python -I scripts/pe_imports.py --baseline a.exe

Exit status:
    0  parsed at least one file successfully
    1  usage error or parse failure
    2  parse succeeded, but --baseline found a Win8+/Win10+ import
"""

from __future__ import annotations

import argparse
import json
import struct
import sys

IMAGE_FILE_MACHINE = {
    0x014C: "i386",
    0x8664: "x86_64",
    0xAA64: "aarch64",
    0x01C4: "arm",
    0x01C0: "arm (old)",
}

# Imports that require a newer OS than the stated baseline. Only functions that
# are statically imported (i.e. resolved by the loader at process start, which
# makes the process fail to launch on older systems) are listed here. Anything
# resolved at runtime via GetProcAddress is deliberately not flagged.
BASELINE_MIN_OS = {
    # Windows 8 / Server 2012
    "WaitOnAddress": "Win8",
    "WakeByAddressSingle": "Win8",
    "WakeByAddressAll": "Win8",
    "GetSystemTimePreciseAsFileTime": "Win8",
    # Windows 10 / Server 2016
    "ProcessPrng": "Win10",
    "SetThreadDescription": "Win10 1607",
    "GetSystemCpuSetInformation": "Win10",
    "SetProcessMitigationPolicy": "Win8",
}

# Function name -> DLL that provides it, used only to annotate the baseline
# report. The check itself is name based because that is what the loader does.
BASELINE_DLL = {
    "WaitOnAddress": "api-ms-win-core-synch-l1-2-0.dll",
    "WakeByAddressSingle": "api-ms-win-core-synch-l1-2-0.dll",
    "WakeByAddressAll": "api-ms-win-core-synch-l1-2-0.dll",
    "ProcessPrng": "bcryptprimitives.dll",
    "GetSystemTimePreciseAsFileTime": "kernel32.dll",
    "SetThreadDescription": "kernel32.dll",
    "GetSystemCpuSetInformation": "kernel32.dll",
    "SetProcessMitigationPolicy": "kernel32.dll",
}


class PeError(Exception):
    pass


def _u16(data, off):
    return struct.unpack_from("<H", data, off)[0]


def _u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def _u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]


def _cstring(data, off):
    if off < 0 or off >= len(data):
        raise PeError("string offset 0x%x out of range" % off)
    end = data.find(b"\0", off)
    if end < 0:
        raise PeError("unterminated string at 0x%x" % off)
    return data[off:end].decode("ascii", "replace")


class Pe:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as fh:
            self.data = fh.read()
        data = self.data
        if len(data) < 0x40 or data[:2] != b"MZ":
            raise PeError("not a PE file (missing MZ header)")
        pe_off = _u32(data, 0x3C)
        if data[pe_off:pe_off + 4] != b"PE\0\0":
            raise PeError("not a PE file (missing PE signature)")
        coff = pe_off + 4
        self.machine = _u16(data, coff)
        self.section_count = _u16(data, coff + 2)
        self.timestamp = _u32(data, coff + 4)
        self.characteristics = _u16(data, coff + 18)
        opt_size = _u16(data, coff + 16)
        self.optional = coff + 20
        if opt_size < 96:
            raise PeError("optional header too small")
        magic = _u16(data, self.optional)
        if magic == 0x10B:
            self.pe32_plus = False
            self.image_base = _u32(data, self.optional + 28)
            dd_off = self.optional + 96
            self.thunk_size = 4
        elif magic == 0x20B:
            self.pe32_plus = True
            self.image_base = _u64(data, self.optional + 24)
            dd_off = self.optional + 112
            self.thunk_size = 8
        else:
            raise PeError("unknown optional header magic 0x%x" % magic)
        self.entry_point = _u32(data, self.optional + 16)
        self.size_of_image = _u32(data, self.optional + 56)
        self.data_dirs = []
        count = _u32(data, dd_off - 4) if opt_size >= (dd_off - self.optional) + 4 else 0
        count = min(count, 16)
        for i in range(count):
            entry = dd_off + i * 8
            if entry + 8 > self.optional + opt_size:
                break
            self.data_dirs.append((_u32(data, entry), _u32(data, entry + 4)))
        self.sections = []
        sec = self.optional + opt_size
        for i in range(self.section_count):
            base = sec + i * 40
            if base + 40 > len(data):
                raise PeError("truncated section table")
            name = data[base:base + 8].rstrip(b"\0").decode("ascii", "replace")
            vsize = _u32(data, base + 8)
            vaddr = _u32(data, base + 12)
            raw_size = _u32(data, base + 16)
            raw_ptr = _u32(data, base + 20)
            self.sections.append((name, vaddr, max(vsize, raw_size), raw_ptr, raw_size))

    # -- address translation -------------------------------------------------
    def rva_to_off(self, rva):
        for _name, vaddr, size, raw_ptr, raw_size in self.sections:
            if vaddr <= rva < vaddr + size:
                delta = rva - vaddr
                if delta >= raw_size:
                    raise PeError("RVA 0x%x points into zero-filled tail" % rva)
                return raw_ptr + delta
        raise PeError("RVA 0x%x not mapped by any section" % rva)

    def data_dir(self, index):
        if index >= len(self.data_dirs):
            return (0, 0)
        return self.data_dirs[index]

    # -- imports -------------------------------------------------------------
    def imports(self):
        rva, size = self.data_dir(1)
        if rva == 0 or size == 0:
            return []
        return self._walk_imports(rva, size, delay=False)

    def delay_imports(self):
        rva, size = self.data_dir(13)
        if rva == 0 or size == 0:
            return []
        return self._walk_imports(rva, size, delay=True)

    def _walk_imports(self, rva, size, delay):
        data = self.data
        off = self.rva_to_off(rva)
        out = []
        # IMAGE_IMPORT_DESCRIPTOR is 20 bytes; IMAGE_DELAYLOAD_DESCRIPTOR is 32.
        desc_size = 32 if delay else 20
        max_desc = max(size // desc_size, 1)
        for i in range(max_desc):
            base = off + i * desc_size
            if base + desc_size > len(data):
                break
            if delay:
                attrs = _u32(data, base)
                name_rva = _u32(data, base + 4)
                iat_rva = _u32(data, base + 12)
                int_rva = _u32(data, base + 16)
                if attrs & 1:
                    # Old-style VA-based descriptors.
                    name_rva -= self.image_base
                    iat_rva -= self.image_base
                    int_rva -= self.image_base
            else:
                int_rva = _u32(data, base)
                name_rva = _u32(data, base + 12)
                iat_rva = _u32(data, base + 16)
            if name_rva == 0:
                break
            dll = _cstring(data, self.rva_to_off(name_rva))
            thunk_rva = int_rva or iat_rva
            functions = []
            if thunk_rva:
                functions = self._walk_thunks(thunk_rva)
            out.append({"dll": dll, "functions": functions})
        return out

    def _walk_thunks(self, rva):
        data = self.data
        off = self.rva_to_off(rva)
        funcs = []
        ordinal_flag = 1 << (self.thunk_size * 8 - 1)
        while True:
            if self.thunk_size == 8:
                value = _u64(data, off)
            else:
                value = _u32(data, off)
            off += self.thunk_size
            if value == 0:
                break
            if value & ordinal_flag:
                funcs.append("#%d" % (value & 0xFFFF))
            else:
                name_rva = value & 0x7FFFFFFF
                name_off = self.rva_to_off(name_rva)
                funcs.append(_cstring(data, name_off + 2))
        return funcs


def describe(pe):
    return {
        "path": pe.path,
        "machine": IMAGE_FILE_MACHINE.get(pe.machine, "0x%04x" % pe.machine),
        "pe32_plus": pe.pe32_plus,
        "image_base": "0x%x" % pe.image_base,
        "size_of_image": pe.size_of_image,
        "imports": pe.imports(),
        "delay_imports": pe.delay_imports(),
    }


def baseline_hits(info):
    hits = []
    for table in ("imports", "delay_imports"):
        for entry in info[table]:
            for fn in entry["functions"]:
                if fn in BASELINE_MIN_OS:
                    hits.append((entry["dll"], fn, BASELINE_MIN_OS[fn]))
    return hits


def print_human(info, show_baseline):
    print("file:      %s" % info["path"])
    print("format:    PE32+ (64-bit)" if info["pe32_plus"] else "format:    PE32 (32-bit)")
    print("machine:   %s" % info["machine"])
    print("imagebase: %s" % info["image_base"])
    total = sum(len(e["functions"]) for e in info["imports"])
    print("imports:   %d DLL(s), %d function(s)" % (len(info["imports"]), total))
    for entry in info["imports"]:
        print("")
        print("  %s" % entry["dll"])
        for fn in entry["functions"]:
            print("      %s" % fn)
    if info["delay_imports"]:
        print("")
        print("delay-loaded imports (resolved only when used):")
        for entry in info["delay_imports"]:
            print("  %s" % entry["dll"])
            for fn in entry["functions"]:
                print("      %s" % fn)
    if show_baseline:
        hits = baseline_hits(info)
        print("")
        if hits:
            print("baseline check: FAIL, %d import(s) require a newer OS" % len(hits))
            for dll, fn, os_name in hits:
                print("    %s!%s  requires %s" % (dll, fn, os_name))
        else:
            print("baseline check: OK, no known Win8+/Win10+ static imports")


def main(argv):
    parser = argparse.ArgumentParser(
        description="Dump PE import tables using only the Python standard library."
    )
    parser.add_argument("files", nargs="+", help="PE files (.exe/.dll/.pyd)")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument(
        "--baseline",
        action="store_true",
        help="flag static imports that require Win8+/Win10+ (exit 2 when found)",
    )
    args = parser.parse_args(argv)

    results = []
    failed = False
    for path in args.files:
        try:
            info = describe(Pe(path))
        except (OSError, PeError, struct.error) as exc:
            print("error: %s: %s" % (path, exc), file=sys.stderr)
            failed = True
            continue
        results.append(info)
        if not args.json:
            if len(results) > 1:
                print("")
            print_human(info, args.baseline)

    if args.json:
        print(json.dumps(results, indent=2))

    if failed:
        return 1
    if args.baseline and any(baseline_hits(r) for r in results):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
