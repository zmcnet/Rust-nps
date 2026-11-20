#!/usr/bin/env python3
"""Black-box interop smoke test: real Go npc client <-> Rust rnps server.

Scope of this file (tools/interop only):
  * build/verify evidence is NOT done here -- the caller passes real binaries in.
  * start an in-process TCP echo target (concurrent, streaming echo)
  * start the Rust server (rnps --config <json>) with NPS_ADMIN_TOKEN in env
  * start the REAL Go npc client (built from resources/nps/cmd/npc)
  * assert the legacy wire handshake, the admin HTTP auth, tunnel lifecycle
    and byte-exact multi-stream concurrent transfer.

Nothing here mocks the protocol on the server side: npc is the real binary and
all assertions are made over real sockets / real HTTP.

Run:
    python -I smoke.py --server-bin <rnps.exe> --npc-bin <npc.exe>

Exit codes:
    0  all checks passed
    1  at least one check failed (logs preserved, tails printed)
    2  usage / local file problem
    3  server binary missing -> end-to-end NOT executed (parent must build)
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.client
import json
import os
import random
import secrets
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback
from pathlib import Path

# --- legacy wire constants (from resources/nps/lib/common/const.go) ---------
CONN_TEST = b"TST"
VERIFY_EER = b"vkey"      # server -> client, auth rejected
VERIFY_SUCCESS = b"sucs"  # server -> client, auth accepted
CORE_VERSION_FALLBACK = "0.26.0"   # version.GetVersion()
FULL_VERSION_FALLBACK = "0.26.10"  # version.VERSION

ONLINE_KEYS = ("online", "is_online", "isOnline", "connected",
               "is_connected", "isConnected", "up", "alive")
ENABLED_KEYS = ("enabled", "is_enabled", "isEnabled", "active")
ID_KEYS = ("id", "client_id", "clientId", "tunnel_id", "tunnelId")

CHUNK = 64 * 1024
KIB = 1024
MIB = 1024 * 1024

# 4 concurrent streams: all > 256 KiB, one >= 4 MiB to cross the 122550
# initial mux window (a 4 MiB stream cannot be fully absorbed by buffering).
STREAM_SIZES = (4 * MIB, 1 * MIB, 512 * KIB, 300 * KIB)


class SmokeFail(Exception):
    """A sequencing check failed; abort the run and report."""


# --------------------------------------------------------------------------
# small utilities
# --------------------------------------------------------------------------
def tail(path: Path, limit: int = 8192) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - limit))
            data = f.read()
        return data.decode("utf-8", "replace")
    except OSError as e:
        return f"<cannot read {path}: {e}>"


def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def unique_ports(count: int) -> list[int]:
    seen: list[int] = []
    while len(seen) < count:
        p = free_port()
        if p not in seen:
            seen.append(p)
    return seen


def recv_exact(sock: socket.socket, n: int, what: str = "") -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError(
                f"peer closed after {len(buf)}/{n} bytes{(' (' + what + ')') if what else ''}")
        buf += chunk
    return bytes(buf)


def wait_until(fn, timeout: float, interval: float = 0.25):
    """Poll fn() until truthy. Returns (ok, last_error).

    A SmokeFail from the predicate aborts immediately (hard sequencing error,
    e.g. the server process died); transient errors are retried.
    """
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            if fn():
                return True, None
        except SmokeFail:
            raise
        except Exception as e:  # keep polling, remember why
            last = e
        time.sleep(interval)
    return False, last


class Checks:
    def __init__(self) -> None:
        self.items: list[tuple[bool, str, str]] = []

    def ok(self, name: str, detail: str = "") -> None:
        self.items.append((True, name, detail))
        print(f"PASS  {name}" + (f"  [{detail}]" if detail else ""))

    def fail(self, name: str, detail: str = "") -> None:
        self.items.append((False, name, detail))
        print(f"FAIL  {name}" + (f"  [{detail}]" if detail else ""))

    @property
    def failures(self) -> list[tuple[bool, str, str]]:
        return [i for i in self.items if not i[0]]


# --------------------------------------------------------------------------
# echo target (in-process, concurrent, streaming)
# --------------------------------------------------------------------------
class EchoServer:
    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]
        self.bytes_echoed = 0
        self.conns = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)

    def start(self) -> "EchoServer":
        self._thread.start()
        return self

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with self._lock:
                self.conns += 1
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        # true streaming echo: read a chunk, write it straight back, loop.
        try:
            conn.settimeout(120)
            while True:
                data = conn.recv(CHUNK)
                if not data:
                    break
                conn.sendall(data)
                with self._lock:
                    self.bytes_echoed += len(data)
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    def stop(self) -> None:
        self._stop.set()
        with contextlib.suppress(OSError):
            self.sock.close()


# --------------------------------------------------------------------------
# processes
# --------------------------------------------------------------------------
def spawn(name: str, argv: list[str], env: dict, log_path: Path,
          cwd: Path | None = None) -> dict:
    log_path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(log_path, "wb")
    shown = " ".join("<redacted-vkey>" if a.startswith("-vkey=") else a for a in argv)
    fh.write(f"# {name}\n# CMD: {shown}\n".encode("utf-8"))
    fh.flush()
    # stdout/stderr go straight to a file: never a PIPE, so a chatty binary
    # can never block on a full buffer.
    proc = subprocess.Popen(
        argv, stdout=fh, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
        env=env, cwd=str(cwd) if cwd else None,
    )
    return {"name": name, "proc": proc, "fh": fh, "log": log_path,
            "wrapper": str(argv[0]).lower().endswith((".cmd", ".bat"))}


def stop_proc(handle: dict | None, timeout: float = 8.0) -> None:
    if not handle:
        return
    proc: subprocess.Popen = handle["proc"]
    if proc.poll() is None and handle.get("wrapper"):
        # A .cmd/.bat wrapper spawns the real process as a child: terminating
        # the wrapper would orphan the child, so kill the whole tree.
        with contextlib.suppress(Exception):
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                           capture_output=True, timeout=15)
    if proc.poll() is None:
        with contextlib.suppress(Exception):
            proc.terminate()  # SIGTERM / TerminateProcess
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            with contextlib.suppress(Exception):
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)],
                               capture_output=True, timeout=15)
            with contextlib.suppress(Exception):
                proc.kill()
            with contextlib.suppress(Exception):
                proc.wait(timeout=5)
    with contextlib.suppress(Exception):
        handle["fh"].close()


def ensure_alive(handle: dict) -> None:
    rc = handle["proc"].poll()
    if rc is not None:
        raise SmokeFail(
            f"{handle['name']} exited unexpectedly (code {rc}).\n"
            f"--- {handle['log']} (tail) ---\n{tail(handle['log'])}")


# --------------------------------------------------------------------------
# HTTP admin API
# --------------------------------------------------------------------------
def http_call(addr: str, method: str, path: str, token: str | None = None,
              body: object | None = None, timeout: float = 10.0):
    host, _, port = addr.rpartition(":")
    conn = http.client.HTTPConnection(host, int(port), timeout=timeout)
    headers = {"Connection": "close", "Accept": "application/json"}
    if token:
        headers["Authorization"] = "Bearer " + token
    payload = None
    if body is not None:
        payload = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    try:
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        data = resp.read()
        return resp.status, dict(resp.getheaders()), data
    finally:
        conn.close()


def parse_json(raw: bytes) -> object:
    if not raw:
        raise ValueError("empty body")
    return json.loads(raw.decode("utf-8", "replace"))


# --------------------------------------------------------------------------
# tolerant field discovery for /api/status (contract owned by the parent agent)
# --------------------------------------------------------------------------
def _is_id(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _match(d: dict, ident: int) -> bool:
    return any(_is_id(d.get(k)) and d.get(k) == ident for k in ID_KEYS)


def _bool_in(d: dict, keys) -> bool | None:
    for k in keys:
        v = d.get(k)
        if isinstance(v, bool):
            return v
        # tolerate textual states: "online"/"offline", "up"/"down", ...
        if isinstance(v, str):
            s = v.strip().lower()
            if s in ("online", "up", "true", "yes", "1", "enabled", "running"):
                return True
            if s in ("offline", "down", "false", "no", "0", "disabled", "stopped"):
                return False
    return None


def find_flag(payload, ident: int, keys, preferred_list: str):
    """Return (found, value). Prefer the named container, then any occurrence.

    Supports both shapes:
        {"clients": [{"id": 1, "online": true}]}
        {"clients": {"1": {"online": true}}}  /  {"clients": {"1": true}}
    """
    def pick(candidates: list[dict]):
        for d in candidates:
            v = _bool_in(d, keys)
            if v is not None:
                return True, v
        return (True, None) if candidates else (False, None)

    def collect_pref(container) -> list[dict]:
        out: list[dict] = []
        if isinstance(container, list):
            out.extend(e for e in container
                       if isinstance(e, dict) and _match(e, ident))
        elif isinstance(container, dict):
            for key in (str(ident), ident):
                if key in container:
                    entry = container[key]
                    if isinstance(entry, bool):
                        return [{keys[0]: entry}]
                    if isinstance(entry, dict):
                        out.append(entry)
                    break
        return out

    if isinstance(payload, dict):
        direct = pick(collect_pref(payload.get(preferred_list)))
        if direct[0]:
            return direct

    all_candidates: list[dict] = []

    def walk(o) -> None:
        if isinstance(o, dict):
            if _match(o, ident):
                all_candidates.append(o)
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(payload)
    return pick(all_candidates)


def tunnel_stats(payload, tunnel_id: int) -> dict | None:
    """Exact lookup of one tunnel row (no fuzzy matching)."""
    if not isinstance(payload, dict):
        return None
    tunnels = payload.get("tunnels")
    if not isinstance(tunnels, list):
        return None
    for entry in tunnels:
        if isinstance(entry, dict) and entry.get("id") == tunnel_id:
            return entry
    return None


def client_row(payload, client_id: int) -> dict | None:
    if not isinstance(payload, dict):
        return None
    clients = payload.get("clients")
    if not isinstance(clients, list):
        return None
    for entry in clients:
        if isinstance(entry, dict) and entry.get("id") == client_id:
            return entry
    return None


def summarize(payload) -> str:
    try:
        text = json.dumps(payload, ensure_ascii=False)
    except Exception:
        text = repr(payload)
    return text[:1200]


# --- exact field contract (nps-server/src/snapshot.rs) ----------------------
# The tolerant find_flag helper above is kept only for diagnostics; acceptance
# below requires these exact keys/types to be present.
CLIENT_FIELDS = (("id", int), ("name", str), ("online", bool), ("version", str))
TUNNEL_FIELDS = (
    ("id", int), ("name", str), ("client_id", int), ("listen_addr", str),
    ("target_addr", str), ("enabled", bool), ("active_connections", int),
    ("bytes_to_client", int), ("bytes_from_client", int),
)


def _field_problems(prefix: str, entry: dict, fields) -> list[str]:
    out: list[str] = []
    for name, typ in fields:
        if name not in entry:
            out.append(f"{prefix}.{name} missing")
            continue
        value = entry[name]
        if typ is bool:
            if not isinstance(value, bool):
                out.append(f"{prefix}.{name} not bool")
        elif typ is int:
            if not isinstance(value, int) or isinstance(value, bool):
                out.append(f"{prefix}.{name} not int")
        elif not isinstance(value, typ):
            out.append(f"{prefix}.{name} not {typ.__name__}")
    return out


def validate_status(payload) -> list[str]:
    """Return a list of contract violations; empty list means exact contract."""
    problems: list[str] = []
    if not isinstance(payload, dict):
        return ["status is not a JSON object"]
    if not isinstance(payload.get("bridge_addr"), str):
        problems.append("bridge_addr missing/not string")

    clients = payload.get("clients")
    if not isinstance(clients, list):
        problems.append("clients missing/not array")
    else:
        for i, entry in enumerate(clients):
            if not isinstance(entry, dict):
                problems.append(f"clients[{i}] not object")
                continue
            problems.extend(_field_problems(f"clients[{i}]", entry, CLIENT_FIELDS))
        if not any(isinstance(e, dict) and e.get("id") == 1 for e in clients):
            problems.append("clients missing id=1")

    tunnels = payload.get("tunnels")
    if not isinstance(tunnels, list):
        problems.append("tunnels missing/not array")
    else:
        for i, entry in enumerate(tunnels):
            if not isinstance(entry, dict):
                problems.append(f"tunnels[{i}] not object")
                continue
            problems.extend(_field_problems(f"tunnels[{i}]", entry, TUNNEL_FIELDS))
            if "last_error" not in entry:
                problems.append(f"tunnels[{i}].last_error missing")
            elif entry["last_error"] is not None and \
                    not isinstance(entry["last_error"], str):
                problems.append(f"tunnels[{i}].last_error not null/string")
        if not any(isinstance(e, dict) and e.get("id") == 1 for e in tunnels):
            problems.append("tunnels missing id=1")
    return problems


# --------------------------------------------------------------------------
# legacy handshake probe (raw socket, exactly what Go's client.NewConn does)
# --------------------------------------------------------------------------
def raw_handshake(addr: str, core_version: str, full_version: str,
                  vkey_hex: str, timeout: float = 6.0):
    """Perform the real legacy handshake.

    Returns (server_digest: bytes, flag: bytes).
    Raises ConnectionError on EOF (server closed, e.g. version mismatch).
    """
    host, _, port = addr.rpartition(":")
    sock = socket.create_connection((host, int(port)), timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(CONN_TEST)
        sock.sendall(struct.pack("<i", len(core_version)) + core_version.encode())
        sock.sendall(struct.pack("<i", len(full_version)) + full_version.encode())
        digest = recv_exact(sock, 32, "server core digest")
        sock.sendall(vkey_hex.encode())
        flag = recv_exact(sock, 4, "verify flag")
        return digest, flag
    finally:
        with contextlib.suppress(OSError):
            sock.close()


def md5_hex(text: str) -> str:
    return hashlib.md5(text.encode()).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def parse_npc_version(npc_bin: str) -> tuple[str, str]:
    cp = subprocess.run([npc_bin, "-version"], capture_output=True, text=True,
                        timeout=30)
    text = (cp.stdout or "") + (cp.stderr or "")
    core = full = ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("Core version:"):
            core = line.split(":", 1)[1].strip()
        elif line.startswith("Version:"):
            full = line.split(":", 1)[1].strip()
    return core, full


# --------------------------------------------------------------------------
# byte-exact streaming transfer with concurrent read/write
# --------------------------------------------------------------------------
def _template(seed: int, size: int = CHUNK) -> bytes:
    r = random.Random(seed)
    randbytes = getattr(r, "randbytes", None)
    if randbytes is not None:
        return randbytes(size)
    return bytes(r.getrandbits(8) for _ in range(size))  # py<3.9 fallback


def _chunk(tpl: bytes, index: int, length: int) -> bytes:
    off = (index * 7) % len(tpl)
    rotated = tpl[off:] + tpl[:off]
    return rotated if length >= len(tpl) else rotated[:length]


def transfer_stream(addr: str, total: int, seed: int, timeout: float = 90.0) -> dict:
    """Send `total` deterministic bytes and require an exact echo, streaming.

    Reader and writer run concurrently so a full socket buffer can never
    deadlock the test itself.
    """
    host, _, port = addr.rpartition(":")
    tpl = _template(seed)
    res = {"ok": False, "sent": 0, "recv": 0,
           "sha_tx": "", "sha_rx": "", "error": None,
           "elapsed": 0.0}
    tx = hashlib.sha256()
    rx = hashlib.sha256()
    started = time.monotonic()
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as sock:
            sock.settimeout(timeout)
            wbox: dict = {}

            def writer() -> None:
                try:
                    off = idx = 0
                    while off < total:
                        n = min(CHUNK, total - off)
                        data = _chunk(tpl, idx, n)
                        sock.sendall(data)
                        tx.update(data)
                        off += n
                        idx += 1
                        res["sent"] = off
                except BaseException as e:  # noqa: BLE001 - reported to caller
                    wbox["err"] = e

            wt = threading.Thread(target=writer, daemon=True)
            wt.start()

            off = idx = 0
            while off < total:
                n = min(CHUNK, total - off)
                expect = _chunk(tpl, idx, n)
                got = recv_exact(sock, n, f"echo seed={seed}")
                if got != expect:
                    diff = next(i for i in range(n) if got[i] != expect[i])
                    raise SmokeFail(
                        f"echoed payload mismatch at stream offset {off + diff} "
                        f"(seed={seed}, size={total})")
                rx.update(got)
                off += n
                idx += 1
                res["recv"] = off

            wt.join(timeout=timeout)
            if wt.is_alive():
                raise SmokeFail(f"writer thread stuck (seed={seed})")
            if "err" in wbox:
                raise wbox["err"]
            res["ok"] = (res["sent"] == total == res["recv"])
    except SmokeFail:
        raise
    except BaseException as e:  # noqa: BLE001
        res["error"] = f"{type(e).__name__}: {e}"
    finally:
        res["elapsed"] = time.monotonic() - started
        res["sha_tx"] = tx.hexdigest()
        res["sha_rx"] = rx.hexdigest()
    return res


def concurrent_transfer(addr: str, sizes, timeout: float, checks: Checks,
                        label: str) -> None:
    barrier = threading.Barrier(len(sizes))
    results: list[dict | None] = [None] * len(sizes)

    def worker(i: int) -> None:
        try:
            barrier.wait(timeout=30)
        except threading.BrokenBarrierError as e:
            results[i] = {"ok": False, "error": f"barrier: {e}"}
            return
        try:
            results[i] = transfer_stream(addr, sizes[i], seed=1000 + i,
                                        timeout=timeout)
        except SmokeFail as e:
            results[i] = {"ok": False, "error": str(e)}
        except BaseException as e:  # noqa: BLE001
            results[i] = {"ok": False, "error": f"{type(e).__name__}: {e}"}

    threads = [threading.Thread(target=worker, args=(i,), daemon=True)
               for i in range(len(sizes))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=timeout + 60)

    all_ok = True
    detail_bits = []
    total_sent = total_recv = 0
    for i, r in enumerate(results):
        if r is None:
            all_ok = False
            detail_bits.append(f"s{i}=no-result")
            continue
        if r.get("ok") and r.get("sha_tx") == r.get("sha_rx"):
            mib = sizes[i] / MIB
            rate = (r["recv"] / max(r["elapsed"], 1e-6)) / MIB
            total_sent += r.get("sent", 0)
            total_recv += r.get("recv", 0)
            detail_bits.append(f"s{i}={sizes[i]}B ok {mib:.2f}MiB {rate:.1f}MiB/s")
        else:
            all_ok = False
            detail_bits.append(f"s{i}={sizes[i]}B FAIL {r.get('error') or 'digest mismatch'}")

    detail = "; ".join(detail_bits)
    if all_ok:
        checks.ok(f"{label}: {len(sizes)} concurrent streams byte-exact", detail)
    else:
        checks.fail(f"{label}: {len(sizes)} concurrent streams byte-exact", detail)
    return {"ok": all_ok, "sent": total_sent, "recv": total_recv}


# --------------------------------------------------------------------------
# probe helpers for "listener really stopped"
# --------------------------------------------------------------------------
def probe_listen(addr: str, timeout: float = 5.0) -> str:
    """Classify a TCP connect attempt.

    Note: on Windows a refused loopback connect can take ~2s to surface
    (WSAECONNREFUSED 10061), so a short timeout would misreport `refused`
    as `timeout`. Callers that assert refusal must allow >= 4s.
    """
    host, _, port = addr.rpartition(":")
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return "connected"
    except ConnectionRefusedError:
        return "refused"
    except socket.timeout:
        return "timeout"
    except OSError as e:
        code = getattr(e, "winerror", None) or e.errno
        if code in (10061, 111, 61):
            return "refused"
        return f"error:{type(e).__name__}:{e}"


def resolve_binary(explicit: str | None, default: Path) -> Path | None:
    if explicit:
        path = Path(explicit).resolve()
        return path if path.is_file() else None
    if default.is_file():
        return default
    if default.suffix == ".exe":
        alt = default.with_suffix("")
        if alt.is_file():
            return alt
    return None


# --------------------------------------------------------------------------
# main flow
# --------------------------------------------------------------------------
def run(args: argparse.Namespace) -> int:
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parents[1]
    checks = Checks()

    server_bin = resolve_binary(
        args.server_bin, repo_root / "rust" / "target" / "debug" / "rnps.exe")
    npc_bin = resolve_binary(
        args.npc_bin, script_dir / "bin" / "npc.exe")

    if npc_bin is None:
        print(f"ERROR: real npc binary not found: "
              f"{args.npc_bin or script_dir / 'bin' / 'npc.exe'}", file=sys.stderr)
        print("       build it with: go build -mod=readonly "
              "-o tools/interop/bin/npc.exe ./cmd/npc", file=sys.stderr)
        return 2
    if server_bin is None:
        print("=" * 72)
        print("END-TO-END NOT EXECUTED: Rust server binary not found.")
        print(f"  looked for: {args.server_bin or repo_root / 'rust' / 'target' / 'debug' / 'rnps.exe'}")
        print("  the parent agent must build it first, e.g.:")
        print("      cd D:/Developing/NPS/rust && cargo build -p nps-app --bin rnps")
        print("  then re-run:")
        print(f"      python -I {Path(__file__).name} --server-bin <rnps.exe> "
              f"--npc-bin {npc_bin}")
        print("=" * 72)
        return 3

    run_dir = script_dir / "logs" / time.strftime("run-%Y%m%d-%H%M%S")
    run_dir.mkdir(parents=True, exist_ok=True)

    # fresh secrets every run; never printed
    admin_token = secrets.token_urlsafe(32)   # >= 24 chars
    vkey = secrets.token_urlsafe(24)

    ports = unique_ports(3)
    bridge_port, web_port, listen_port = ports
    bridge_addr = f"127.0.0.1:{bridge_port}"
    web_addr = f"127.0.0.1:{web_port}"
    listen_addr = f"127.0.0.1:{listen_port}"

    echo = EchoServer().start()
    target_addr = f"127.0.0.1:{echo.port}"

    config = {
        "bridge_addr": bridge_addr,
        "web_addr": web_addr,
        "clients": [{"id": 1, "name": "legacy-test", "vkey": vkey}],
        "tunnels": [{
            "id": 1,
            "name": "echo-test",
            "client_id": 1,
            "listen_addr": listen_addr,
            "target_addr": target_addr,
            "enabled": True,
        }],
    }
    config_path = run_dir / "rnps.json"
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")

    env = dict(os.environ)
    env["NPS_ADMIN_TOKEN"] = admin_token

    # npc gets a clean env: the admin token must never leak to the client.
    npc_env = {k: v for k, v in os.environ.items() if k != "NPS_ADMIN_TOKEN"}

    server = None
    npc = None
    status_cache: dict = {"payload": None, "raw": b""}
    seen_bodies: list[tuple[str, bytes]] = []
    core_version, full_version = CORE_VERSION_FALLBACK, FULL_VERSION_FALLBACK

    def record_body(label: str, raw: bytes) -> None:
        """Keep every admin API response body for the secret-leak assertion."""
        seen_bodies.append((label, raw))

    def scan_for_secrets(record: bool = True) -> None:
        """No admin response may contain the test vkey, md5(vkey) or token."""
        needles = {
            "plain vkey": vkey.encode(),
            "md5(vkey)": md5_hex(vkey).encode(),
            "admin token": admin_token.encode(),
        }
        for label, raw in seen_bodies:
            for what, needle in needles.items():
                if needle and needle in raw:
                    raise SmokeFail(
                        f"secret leak: {label} response contains {what}")
        if record:
            checks.ok("admin API responses contain no vkey / md5(vkey) / token",
                      f"{len(seen_bodies)} response bodies scanned")

    def fetch_status() -> object:
        code, _, raw = http_call(web_addr, "GET", "/api/status",
                                 token=admin_token, timeout=10)
        record_body("GET /api/status", raw)
        if code != 200:
            # plain RuntimeError: transient, wait_until keeps retrying
            raise RuntimeError(f"GET /api/status -> {code}: {raw[:200]!r}")
        payload = parse_json(raw)
        problems = validate_status(payload)
        if problems:
            raise SmokeFail(
                "status violates the exact clients/tunnels contract: "
                + "; ".join(problems[:8]))
        status_cache["payload"] = payload
        status_cache["raw"] = raw
        return payload

    def client_online() -> bool:
        """Exact contract: clients[] row id=1 with boolean `online`."""
        payload = fetch_status()
        row = client_row(payload, 1)
        if row is None:
            raise SmokeFail(
                "status has no clients[] row with id=1; payload="
                + summarize(payload))
        return bool(row["online"])

    def tunnel_enabled() -> bool | None:
        """Exact contract: tunnels[] row id=1 with boolean `enabled`."""
        payload = fetch_status()
        row = tunnel_stats(payload, 1)
        if row is None:
            raise SmokeFail(
                "status has no tunnels[] row with id=1; payload="
                + summarize(payload))
        return row["enabled"]

    try:
        # ---------------- 0. binaries / version evidence ----------------
        print(f"npc binary: {npc_bin}")
        print(f"  size={npc_bin.stat().st_size} bytes sha256={sha256_file(npc_bin)}")
        core_version, full_version = parse_npc_version(str(npc_bin))
        if core_version:
            checks.ok("npc -version reports core version",
                      f"core={core_version} full={full_version or '?'}")
            if core_version == CORE_VERSION_FALLBACK and \
                    full_version == FULL_VERSION_FALLBACK:
                checks.ok("npc version matches expected v0.26.10 build")
            else:
                checks.fail(
                    "npc version matches expected v0.26.10 build",
                    f"got core={core_version} full={full_version}; expected "
                    f"core={CORE_VERSION_FALLBACK} full={FULL_VERSION_FALLBACK}")
        else:
            checks.fail("npc -version reports core version", "unparsable output")
            core_version = CORE_VERSION_FALLBACK
        full_version = full_version or FULL_VERSION_FALLBACK

        # ---------------- 1. start server ----------------
        print(f"\n-- starting server: {server_bin}")
        try:
            server = spawn("rnps", [str(server_bin), "--config", str(config_path)],
                           env=env, log_path=run_dir / "rnps.log", cwd=run_dir)
        except OSError as e:
            raise SmokeFail(f"failed to start server {server_bin}: {e}")

        def ports_ready() -> bool:
            ensure_alive(server)
            return all(probe_listen(a, 0.5) == "connected"
                       for a in (bridge_addr, web_addr))

        ok, err = wait_until(ports_ready, args.startup_timeout)
        if not ok:
            raise SmokeFail(
                f"server did not open bridge {bridge_addr} + web {web_addr} "
                f"within {args.startup_timeout}s"
                + (f"; last error: {err}" if err else ""))
        checks.ok("server listens on bridge_addr and web_addr",
                  f"{bridge_addr} {web_addr}")

        # ---------------- 2. admin auth (black box) ----------------
        code, _, raw = http_call(web_addr, "GET", "/api/status", timeout=10)
        record_body("GET /api/status (no token)", raw)
        if code == 401:
            checks.ok("GET /api/status without token -> 401")
        else:
            checks.fail("GET /api/status without token -> 401",
                        f"got {code}: {raw[:200]!r}")

        code, _, raw = http_call(web_addr, "GET", "/api/status",
                                 token="wrong-token-not-the-admin-token",
                                 timeout=10)
        record_body("GET /api/status (wrong token)", raw)
        if code in (401, 403):
            checks.ok("GET /api/status with wrong Bearer -> denied",
                      f"status {code}")
        else:
            checks.fail("GET /api/status with wrong Bearer -> denied",
                        f"got {code}: {raw[:200]!r}")

        code, _, raw = http_call(web_addr, "GET", "/api/status",
                                 token=admin_token, timeout=10)
        record_body("GET /api/status (valid token)", raw)
        if code == 200:
            checks.ok("GET /api/status with Bearer -> 200")
            try:
                payload = parse_json(raw)
                problems = validate_status(payload)
                if problems:
                    checks.fail("status matches exact clients/tunnels contract",
                                "; ".join(problems[:8]))
                    raise SmokeFail("status contract invalid at first fetch")
                checks.ok("status matches exact clients/tunnels contract")
                status_cache["payload"] = payload
            except ValueError as e:
                checks.fail("status matches exact clients/tunnels contract",
                            f"invalid JSON: {e}")
                raise SmokeFail("status body is not valid JSON")
        else:
            checks.fail("GET /api/status with Bearer -> 200",
                        f"got {code}: {raw[:200]!r}")
            raise SmokeFail("admin API unusable, cannot observe state")

        # early leak assertion on the unauthenticated + authenticated bodies
        scan_for_secrets(record=False)

        # ---------------- 3. legacy handshake / version / wrong vkey -------
        expected_digest = md5_hex(core_version)
        digests_ok = True
        try:
            digest, flag = raw_handshake(bridge_addr, core_version, full_version,
                                         md5_hex("definitely-wrong-vkey"))
        except (ConnectionError, OSError) as e:
            digests_ok = False
            checks.fail(
                f"legacy handshake accepts core version {core_version}",
                f"server closed the connection: {e}")
            # diagnose which core versions the server actually accepts
            accepted = []
            for probe in {CORE_VERSION_FALLBACK, FULL_VERSION_FALLBACK,
                          "0.26.0", "0.26.10"}:
                try:
                    raw_handshake(bridge_addr, probe, full_version,
                                  md5_hex("definitely-wrong-vkey"), timeout=4)
                    accepted.append(probe)
                except (ConnectionError, OSError):
                    pass
            print(f"INFO  server core versions accepted on handshake: "
                  f"{accepted or 'none'}")
            raise SmokeFail(
                "the real Go npc would abort at the version check; server must "
                f"expect core version '{core_version}' (GetVersion()), "
                f"not the full VERSION")

        if digests_ok:
            if digest == expected_digest.encode():
                checks.ok("server returns md5(core_version) digest",
                          digest.decode("ascii", "replace"))
            else:
                checks.fail("server returns md5(core_version) digest",
                            f"expected {expected_digest}; got "
                            f"{digest.decode('ascii', 'replace')}")

            if flag == VERIFY_EER:
                checks.ok("wrong vkey -> handshake flag 'vkey'")
            else:
                checks.fail("wrong vkey -> handshake flag 'vkey'",
                            f"got {flag!r}")

        # ---------------- 4. real npc with WRONG vkey must be rejected ------
        wrong_npc_argv = [str(npc_bin), f"-server={bridge_addr}",
                          f"-vkey={secrets.token_urlsafe(24)}", "-type=tcp"]
        wrong_npc = spawn("npc-badvkey", wrong_npc_argv, env=npc_env,
                          log_path=run_dir / "npc-bad-vkey.log", cwd=run_dir)
        try:
            time.sleep(min(6.0, args.startup_timeout))
            ensure_alive(wrong_npc)
            still_offline = not client_online()
            bad_log = tail(wrong_npc["log"], 16384)
            if still_offline and "incorrect" in bad_log.lower():
                checks.ok("real npc with wrong vkey rejected by server",
                          "client stays offline; npc logged 'Validation key ... incorrect'")
            elif still_offline:
                checks.fail("real npc with wrong vkey rejected by server",
                            "client offline but no rejection message in npc log")
            else:
                checks.fail("real npc with wrong vkey rejected by server",
                            "client id=1 came online with a bogus vkey")
        finally:
            stop_proc(wrong_npc, timeout=8)

        # ---------------- 5. start REAL npc, wait online ----------------
        print(f"\n-- starting real npc: {npc_bin}")
        npc_argv = [str(npc_bin), f"-server={bridge_addr}",
                    f"-vkey={vkey}", "-type=tcp"]
        npc = spawn("npc", npc_argv, env=npc_env, log_path=run_dir / "npc.log",
                    cwd=run_dir)

        def npc_online() -> bool:
            ensure_alive(npc)
            return client_online()

        ok, err = wait_until(npc_online, args.online_timeout)
        if not ok:
            raise SmokeFail(
                f"client id=1 never became online within {args.online_timeout}s"
                + (f"; last error: {err}" if err else "")
                + f"; last /api/status={summarize(status_cache['payload'])}")
        checks.ok("real Go npc registered, client id=1 online")

        # ---------------- 6. concurrent byte-exact transfer ----------------
        # wait for the public listener to actually accept before streaming
        ok, _ = wait_until(lambda: probe_listen(listen_addr, 1.0) == "connected",
                           args.state_timeout)
        if not ok:
            raise SmokeFail(f"public tunnel {listen_addr} did not start listening")
        moved = concurrent_transfer(listen_addr, STREAM_SIZES, args.transfer_timeout,
                                    checks, "concurrent echo")

        # Server-side byte accounting must reflect at least the business bytes
        # and all transfer sockets must be released (active_connections -> 0).
        if moved["ok"]:
            expected_bytes = sum(STREAM_SIZES)

            def stats_settled() -> bool:
                row = tunnel_stats(fetch_status(), 1)
                if row is None:
                    return False
                return (row["active_connections"] == 0
                        and row["bytes_to_client"] >= expected_bytes
                        and row["bytes_from_client"] >= expected_bytes)

            ok, err = wait_until(stats_settled, args.state_timeout + 10)
            row = tunnel_stats(fetch_status(), 1) or {}
            detail = (f"active_connections={row.get('active_connections')} "
                      f"bytes_to_client={row.get('bytes_to_client')} "
                      f"bytes_from_client={row.get('bytes_from_client')} "
                      f"expected>={expected_bytes}")
            if ok:
                checks.ok("tunnel stats settle after big transfer", detail)
            else:
                checks.fail("tunnel stats settle after big transfer", detail)

        # ---------------- 7. client disconnect / reconnect ----------------
        stop_proc(npc, timeout=10)
        npc = None

        ok, err = wait_until(lambda: not client_online(), args.offline_timeout)
        if ok:
            checks.ok("client id=1 online=false after npc shutdown")
        else:
            checks.fail("client id=1 online=false after npc shutdown",
                        f"still online after {args.offline_timeout}s"
                        + (f"; last error: {err}" if err else "")
                        + f"; payload={summarize(status_cache['payload'])}")

        npc = spawn("npc", npc_argv, env=npc_env, log_path=run_dir / "npc-restart.log",
                    cwd=run_dir)
        ok, err = wait_until(npc_online, args.online_timeout)
        if ok:
            checks.ok("client id=1 online=true after npc restart")
            r = transfer_stream(listen_addr, 128 * KIB, seed=7777,
                                timeout=args.transfer_timeout)
            if r["ok"] and r["sha_tx"] == r["sha_rx"]:
                checks.ok("transfer works after reconnect",
                          f"128KiB sha256={r['sha_rx'][:16]}...")
            else:
                checks.fail("transfer works after reconnect",
                            str(r.get("error") or "digest mismatch"))
        else:
            checks.fail("client id=1 online=true after npc restart",
                        f"not online after {args.online_timeout}s"
                        + (f"; last error: {err}" if err else ""))

        # ---------------- 8. tunnel enable/disable (real listener) ---------
        code, _, raw = http_call(web_addr, "POST", "/api/tunnels/1/state",
                                 token=admin_token, body={"enabled": False},
                                 timeout=10)
        record_body("POST /api/tunnels/1/state {enabled:false}", raw)
        if 200 <= code < 300:
            checks.ok("POST /api/tunnels/1/state {enabled:false} accepted",
                      f"status {code}")
        else:
            checks.fail("POST /api/tunnels/1/state {enabled:false} accepted",
                        f"got {code}: {raw[:200]!r}")

        ok, _ = wait_until(lambda: tunnel_enabled() is False, args.state_timeout)
        if ok:
            checks.ok("status reports tunnel 1 enabled=false")
        else:
            checks.fail("status reports tunnel 1 enabled=false",
                        f"got {tunnel_enabled()}; payload="
                        f"{summarize(status_cache['payload'])}")

        def public_port_closed() -> bool:
            # Strict: disabling must RELEASE the listener, i.e. connect must be
            # actively refused. A socket that still accepts but does not
            # forward traffic is NOT proof of release. Timeout must exceed the
            # ~2s Windows refusal latency, else refused looks like timeout.
            return probe_listen(listen_addr, args.refuse_probe_timeout) == "refused"

        ok, _ = wait_until(public_port_closed, args.state_timeout)
        if ok:
            checks.ok("public listen port really released (connection refused)")
        else:
            state = probe_listen(listen_addr, args.refuse_probe_timeout)
            checks.fail("public listen port really released (connection refused)",
                        f"{listen_addr} probe state: {state} after disable"
                        + (" (timeout is NOT proof of release)" if state == "timeout"
                           else ""))

        code, _, raw = http_call(web_addr, "POST", "/api/tunnels/1/state",
                                 token=admin_token, body={"enabled": True},
                                 timeout=10)
        record_body("POST /api/tunnels/1/state {enabled:true}", raw)
        if 200 <= code < 300:
            checks.ok("POST /api/tunnels/1/state {enabled:true} accepted",
                      f"status {code}")
        else:
            checks.fail("POST /api/tunnels/1/state {enabled:true} accepted",
                        f"got {code}: {raw[:200]!r}")

        ok, _ = wait_until(lambda: tunnel_enabled() is True, args.state_timeout)
        if ok:
            checks.ok("status reports tunnel 1 enabled=true")
        else:
            checks.fail("status reports tunnel 1 enabled=true",
                        f"got {tunnel_enabled()}; payload={summarize(status_cache['payload'])}")

        def public_port_live() -> bool:
            try:
                r = transfer_stream(listen_addr, 64 * KIB, seed=99, timeout=15)
            except SmokeFail:
                return False
            return r["ok"] and r["sha_tx"] == r["sha_rx"]

        ok, _ = wait_until(public_port_live, args.state_timeout)
        if ok:
            checks.ok("public listen port resumes service after enable")
        else:
            checks.fail("public listen port resumes service after enable",
                        "64KiB echo did not complete")

        # ---------------- 8c. secret-leak assertion (all admin bodies) ------
        scan_for_secrets(record=True)

        # ---------- 8d. optional interactive preview (default off) ----------
        # Keeps the exact same real npc/rnps/echo environment alive for a
        # browser check. The test-only admin token is written to
        # run_dir/ui-session.json only, never to stdout.
        if args.preview_seconds > 0:
            if checks.failures:
                print("preview skipped: earlier checks failed")
            else:
                session = {
                    "web_addr": web_addr,
                    "bridge_addr": bridge_addr,
                    "listen_addr": listen_addr,
                    "target_addr": target_addr,
                    "admin_token": admin_token,
                    "rnps_bin": str(server_bin),
                    "npc_bin": str(npc_bin),
                    "rnps_log": str(server["log"]),
                    "npc_log": str(npc["log"]),
                    "run_dir": str(run_dir),
                    "preview_seconds": args.preview_seconds,
                    "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                }
                session_path = run_dir / "ui-session.json"
                session_path.write_text(
                    json.dumps(session, indent=2), encoding="utf-8")
                with contextlib.suppress(OSError):
                    os.chmod(session_path, 0o600)
                print(f"\n-- preview active for {args.preview_seconds:.0f}s; "
                      f"session file: {session_path} (token not printed)")
                deadline = time.monotonic() + args.preview_seconds
                stayed_up = True
                while time.monotonic() < deadline:
                    if server["proc"].poll() is not None or \
                            (npc is not None and npc["proc"].poll() is not None):
                        stayed_up = False
                        break
                    time.sleep(0.5)
                if stayed_up:
                    checks.ok("preview environment stayed up",
                              f"{args.preview_seconds:.0f}s")
                else:
                    checks.fail("preview environment stayed up",
                                "a server/npc process exited during preview")

    except SmokeFail as e:
        checks.fail("run aborted", str(e))
        print(f"\n--- FAILURE ---\n{e}\n")
        for h in (npc, server):
            if h:
                print(f"--- {h['log']} (tail) ---\n{tail(h['log'])}\n")
    except KeyboardInterrupt:
        print("\ninterrupted by user")
        return 130
    except BaseException:  # noqa: BLE001 - unexpected bug, still clean up
        traceback.print_exc()
        for h in (npc, server):
            if h:
                print(f"--- {h['log']} (tail) ---\n{tail(h['log'])}\n")
        return 1
    finally:
        stop_proc(npc)
        stop_proc(server)
        echo.stop()

    # ---------------- 9. cleanup verification ----------------
    # Give the OS a moment; check for real LISTENING sockets only (TIME_WAIT
    # from our own test connections is expected and harmless).
    def listening(addr: str) -> bool:
        host, _, port = addr.rpartition(":")
        try:
            lines = subprocess.run(
                ["netstat", "-ano", "-p", "TCP"], capture_output=True,
                text=True, timeout=8).stdout.splitlines()
            needle = f"{host}:{port}"
            return any(needle in ln and "LISTENING" in ln.upper() for ln in lines)
        except Exception:
            return probe_listen(addr, 0.5) == "connected"

    time.sleep(0.4)
    leftovers = []
    for label, addr in (("bridge", bridge_addr), ("web", web_addr),
                        ("listen", listen_addr), ("echo", target_addr)):
        if listening(addr):
            leftovers.append(f"{label} {addr}")
    if leftovers:
        checks.fail("no test sockets left listening", ", ".join(leftovers))
    else:
        checks.ok("all spawned processes/sockets cleaned up")

    print("\nlogs kept at:", run_dir)
    print("artifacts: config.json (contains test-only temp secrets), "
          "rnps.log, npc.log, npc-restart.log")

    failures = checks.failures
    total = len(checks.items)
    print(f"\n==== {total - len(failures)}/{total} checks passed ====")
    real_bin = server_bin.name.lower() in ("rnps", "rnps.exe")
    if failures:
        print("failed checks:")
        for _, name, detail in failures:
            print(f"  - {name}" + (f": {detail}" if detail else ""))
        return 1
    if not real_bin:
        # Guard against a stand-in server being mistaken for evidence.
        print(f"RESULT: harness self-test OK -- NOT real rnps interop "
              f"(server was {server_bin.name})")
        return 0
    print("RESULT: OK (real Go npc <-> Rust rnps interop verified)")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Black-box interop smoke test for the Rust rnps server "
                    "against the real Go npc client.")
    p.add_argument("--server-bin", help="path to rnps.exe "
                   "(default: <repo>/rust/target/debug/rnps.exe)")
    p.add_argument("--npc-bin", help="path to the real Go npc.exe "
                   "(default: <script dir>/bin/npc.exe)")
    p.add_argument("--startup-timeout", type=float, default=30.0,
                   help="seconds to wait for bridge+web listeners (default 30)")
    p.add_argument("--online-timeout", type=float, default=45.0,
                   help="seconds to wait for client id=1 online (default 45)")
    p.add_argument("--offline-timeout", type=float, default=60.0,
                   help="seconds to wait for online=false (default 60; the Go "
                        "server uses a 60s disconnect check interval)")
    p.add_argument("--transfer-timeout", type=float, default=120.0,
                   help="per-socket operation timeout for transfers (default 120)")
    p.add_argument("--state-timeout", type=float, default=20.0,
                   help="seconds to wait for tunnel state to take effect "
                        "(default 20)")
    p.add_argument("--refuse-probe-timeout", type=float, default=6.0,
                   help="connect timeout used when asserting a disabled port "
                        "is refused; must exceed the ~2s Windows refusal "
                        "latency (default 6)")
    p.add_argument("--preview-seconds", type=float, default=0.0,
                   help="after a successful run, keep the same real "
                        "npc/rnps/echo environment alive this long for a "
                        "browser check (0 = off, max 600); the test-only "
                        "token is written to run_dir/ui-session.json")
    args = p.parse_args(argv)
    if args.preview_seconds < 0 or args.preview_seconds > 600:
        p.error("--preview-seconds must be between 0 and 600")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
