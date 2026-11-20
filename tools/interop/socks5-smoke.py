#!/usr/bin/env python3
"""Black-box interop smoke test: real Go npc (mode=socks5) <-> Rust SOCKS5 server.

What is real here:
  * the Rust SOCKS5 implementation under test (crates/nps-server/src/socks5.rs)
    is driven through a small host binary compiled from
    crates/nps-server/tests/socks5.rs (`interop_host_for_real_npc`);
  * the Go client is the REAL npc.exe (built from resources/nps/cmd/npc),
    started with `-server=<bridge> -vkey=<vkey> -type=tcp` -- exactly the
    configuration that nps itself uses for `mode=socks5` (in original nps the
    SOCKS5 server lives on the SERVER side; the npc needs no extra flags);
  * the SOCKS5 client is hand-written on top of the standard library socket
    module: full greeting / RFC 1929 auth / CONNECT / UDP ASSOCIATE;
  * the target is a real TCP echo server, and payloads are compared
    byte-for-byte.

Nothing mocks the legacy bridge protocol or the mux: npc does the real
handshake, the real mux, and the real dial of the target host.

Run:
    python -I socks5-smoke.py --cargo-bin <cargo.exe> --npc-bin <npc.exe>
    python -I socks5-smoke.py            # auto-detect both

Exit codes:
    0  all checks passed
    1  at least one check failed (log tails printed)
    2  usage / local file problem (missing npc or cargo)
    3  end-to-end NOT executed (host binary build failed)

Standard library only; safe to run with `python -I`.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from pathlib import Path

# ---------------------------------------------------------------------------
# SOCKS5 constants (RFC 1928 / RFC 1929)
# ---------------------------------------------------------------------------
VER = 5
METHOD_NO_AUTH = 0x00
METHOD_USERPASS = 0x02
METHOD_NONE_ACCEPTABLE = 0xFF
AUTH_VER = 1

CMD_CONNECT = 0x01
CMD_BIND = 0x02
CMD_UDP_ASSOCIATE = 0x03

ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

REP_SUCCEEDED = 0x00
REP_GENERAL_FAILURE = 0x01
REP_HOST_UNREACHABLE = 0x04
REP_COMMAND_NOT_SUPPORTED = 0x07
REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08

CHUNK = 64 * 1024
KIB = 1024
MIB = 1024 * 1024


class SmokeFail(Exception):
    """A hard sequencing failure: abort immediately."""


class Checks:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0
        self.failures: list[str] = []

    def ok(self, label: str, detail: str = "") -> None:
        self.passed += 1
        suffix = f"  [{detail}]" if detail else ""
        print(f"  PASS  {label}{suffix}")

    def fail(self, label: str, detail: str = "") -> None:
        self.failed += 1
        msg = f"{label}: {detail}" if detail else label
        self.failures.append(msg)
        print(f"  FAIL  {label}" + (f"  [{detail}]" if detail else ""))

    def expect(self, cond: bool, label: str, detail: str = "") -> bool:
        if cond:
            self.ok(label, detail)
        else:
            self.fail(label, detail)
        return cond


# ---------------------------------------------------------------------------
# utilities
# ---------------------------------------------------------------------------
def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def unique_ports(n: int) -> list[int]:
    seen: list[int] = []
    while len(seen) < n:
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
                f"peer closed after {len(buf)}/{n} bytes"
                + (f" ({what})" if what else "")
            )
        buf += chunk
    return bytes(buf)


def tail(path: Path, limit: int = 8192) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - limit))
            return f.read().decode("utf-8", "replace")
    except OSError as e:
        return f"<cannot read {path}: {e}>"


def resolve_binary(explicit: str | None, default: Path) -> Path | None:
    if explicit:
        p = Path(explicit).resolve()
        return p if p.is_file() else None
    if default.is_file():
        return default
    if default.suffix == ".exe" and default.with_suffix("").is_file():
        return default.with_suffix("")
    return None


def wait_until(fn, timeout: float, interval: float = 0.1):
    """Poll fn() until truthy. Returns (ok, last_error)."""
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            if fn():
                return True, None
        except SmokeFail:
            raise
        except Exception as e:  # transient
            last = e
        time.sleep(interval)
    return False, last


# ---------------------------------------------------------------------------
# real UDP echo target (for UDP ASSOCIATE)
# ---------------------------------------------------------------------------
class UdpEchoServer:
    """UDP echo: each datagram is sent straight back to its source."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.datagrams = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def start(self) -> "UdpEchoServer":
        self._thread.start()
        return self

    def _loop(self) -> None:
        self.sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                data, src = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                return
            self.datagrams += 1
            try:
                self.sock.sendto(data, src)
            except OSError:
                return

    def stop(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass


def socks5_udp_header(atyp: int, host: str, port: int) -> bytes:
    """`RSV(2) FRAG(1) ATYP ADDR PORT` prefix of a SOCKS5 UDP datagram."""
    if atyp == ATYP_IPV4:
        addr = socket.inet_aton(host)
    elif atyp == ATYP_IPV6:
        addr = socket.inet_pton(socket.AF_INET6, host)
    elif atyp == ATYP_DOMAIN:
        raw = host.encode()
        addr = bytes([len(raw)]) + raw
    else:
        raise ValueError(atyp)
    return b"\x00\x00\x00" + bytes([atyp]) + addr + struct.pack("!H", port)


# ---------------------------------------------------------------------------
# real TCP echo target
# ---------------------------------------------------------------------------
class EchoServer:
    """Streaming echo: reads a chunk, writes it straight back."""

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
            try:
                conn.close()
            except OSError:
                pass

    def stop(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# hand-written SOCKS5 client (stdlib only)
# ---------------------------------------------------------------------------
class Socks5Client:
    def __init__(self, proxy: tuple[str, int], timeout: float = 15.0) -> None:
        self.sock = socket.create_connection(proxy, timeout=timeout)
        self.sock.settimeout(timeout)
        self.method: int | None = None

    # -- greeting / auth ------------------------------------------------
    def negotiate(self, credentials: tuple[str, str] | None = None) -> int:
        """Send greeting (+ optional auth). Returns the chosen method."""
        methods = [METHOD_NO_AUTH]
        if credentials is not None:
            methods = [METHOD_NO_AUTH, METHOD_USERPASS]
        self.sock.sendall(bytes([VER, len(methods)]) + bytes(methods))
        ver, method = recv_exact(self.sock, 2, "greeting reply")
        if ver != VER:
            raise SmokeFail(f"greeting reply VER={ver}, expected {VER}")
        self.method = method

        if method == METHOD_USERPASS:
            if credentials is None:
                raise SmokeFail("server demanded auth but no credentials given")
            user, password = credentials
            u = user.encode()
            p = password.encode()
            self.sock.sendall(
                bytes([AUTH_VER, len(u)]) + u + bytes([len(p)]) + p
            )
            aver, status = recv_exact(self.sock, 2, "auth reply")
            if aver != AUTH_VER:
                raise SmokeFail(f"auth reply VER={aver}, expected {AUTH_VER}")
            if status != 0:
                raise SmokeFail(f"auth rejected, STATUS={status}")
        elif method == METHOD_NONE_ACCEPTABLE:
            raise SmokeFail("server replied 0xFF (no acceptable method)")
        return method

    def auth_only_raw(self, user: str, password: str) -> tuple[int, int]:
        """Greeting that only offers user/pass; returns (method, status)."""
        self.sock.sendall(bytes([VER, 1, METHOD_USERPASS]))
        ver, method = recv_exact(self.sock, 2, "greeting reply")
        if ver != VER:
            raise SmokeFail(f"greeting reply VER={ver}")
        if method != METHOD_USERPASS:
            return method, -1
        u = user.encode()
        p = password.encode()
        self.sock.sendall(bytes([AUTH_VER, len(u)]) + u + bytes([len(p)]) + p)
        aver, status = recv_exact(self.sock, 2, "auth reply")
        if aver != AUTH_VER:
            raise SmokeFail(f"auth reply VER={aver}")
        return method, status

    # -- request --------------------------------------------------------
    def _addr_bytes(self, atyp: int, addr) -> bytes:
        if atyp == ATYP_IPV4:
            return socket.inet_aton(addr)
        if atyp == ATYP_IPV6:
            return socket.inet_pton(socket.AF_INET6, addr)
        if atyp == ATYP_DOMAIN:
            raw = addr.encode()
            return bytes([len(raw)]) + raw
        raise ValueError(f"bad atyp {atyp}")

    def request(self, cmd: int, atyp: int, addr, port: int) -> tuple[int, tuple]:
        payload = (
            bytes([VER, cmd, 0x00, atyp])
            + self._addr_bytes(atyp, addr)
            + struct.pack("!H", port)
        )
        self.sock.sendall(payload)
        return self.read_reply()

    def read_reply(self) -> tuple[int, tuple]:
        ver, rep, rsv, atyp = recv_exact(self.sock, 4, "request reply")
        if ver != VER:
            raise SmokeFail(f"reply VER={ver}, expected {VER}")
        if rsv != 0:
            raise SmokeFail(f"reply RSV={rsv}, expected 0")
        if atyp == ATYP_IPV4:
            host = socket.inet_ntoa(recv_exact(self.sock, 4))
        elif atyp == ATYP_IPV6:
            host = socket.inet_ntop(socket.AF_INET6, recv_exact(self.sock, 16))
        elif atyp == ATYP_DOMAIN:
            n = recv_exact(self.sock, 1)[0]
            host = recv_exact(self.sock, n).decode()
        else:
            raise SmokeFail(f"reply ATYP={atyp} not supported by this test client")
        (port,) = struct.unpack("!H", recv_exact(self.sock, 2))
        return rep, (host, port)

    # -- data -----------------------------------------------------------
    def send(self, data: bytes) -> None:
        self.sock.sendall(data)

    def recv_exactly(self, n: int) -> bytes:
        return recv_exact(self.sock, n, "payload")

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def connect_via_socks(
    proxy: tuple[str, int],
    target: tuple[str, int],
    credentials: tuple[str, str] | None = None,
    atyp: int = ATYP_IPV4,
) -> Socks5Client:
    c = Socks5Client(proxy)
    c.negotiate(credentials)
    rep, _ = c.request(CMD_CONNECT, atyp, target[0], target[1])
    if rep != REP_SUCCEEDED:
        c.close()
        raise SmokeFail(f"CONNECT failed, REP={rep}")
    return c


# ---------------------------------------------------------------------------
# process helpers
# ---------------------------------------------------------------------------
def spawn(name: str, argv: list[str], log_path: Path, env: dict | None = None,
          cwd: Path | None = None):
    log = open(log_path, "wb")
    proc = subprocess.Popen(
        argv, stdout=log, stderr=subprocess.STDOUT,
        cwd=str(cwd or log_path.parent),
        env=env,
    )
    return {"name": name, "proc": proc, "log": log_path, "handle": log}


def ensure_alive(handle) -> None:
    if handle is None:
        return
    code = handle["proc"].poll()
    if code is not None:
        raise SmokeFail(
            f"{handle['name']} exited with code {code}; log:\n"
            + tail(handle["log"], 4096)
        )


def stop_proc(handle, timeout: float = 8.0) -> None:
    if handle is None:
        return
    proc = handle["proc"]
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
    try:
        handle["handle"].close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def run(args: argparse.Namespace) -> int:
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parents[1]
    checks = Checks()

    cargo_bin = resolve_binary(
        args.cargo_bin, Path(os.environ.get("CARGO_HOME", Path.home() / ".cargo"))
        / "bin" / "cargo.exe")
    if cargo_bin is None:
        import shutil
        found = shutil.which("cargo")
        cargo_bin = Path(found) if found else None
    npc_bin = resolve_binary(args.npc_bin, script_dir / "bin" / "npc.exe")

    if npc_bin is None:
        print(f"ERROR: real npc binary not found: "
              f"{args.npc_bin or script_dir / 'bin' / 'npc.exe'}", file=sys.stderr)
        print("       build it with: go build -mod=readonly "
              "-o tools/interop/bin/npc.exe ./cmd/npc", file=sys.stderr)
        return 2
    if cargo_bin is None:
        print("ERROR: cargo not found; pass --cargo-bin <cargo.exe>", file=sys.stderr)
        return 2

    run_dir = script_dir / "logs" / time.strftime("socks5-%Y%m%d-%H%M%S")
    run_dir.mkdir(parents=True, exist_ok=True)

    vkey = secrets.token_urlsafe(24)
    bridge_port, socks_port, authed_port, bridge2_port = unique_ports(4)
    bridge_addr = f"127.0.0.1:{bridge_port}"
    bridge2_addr = f"127.0.0.1:{bridge2_port}"
    socks_addr = f"127.0.0.1:{socks_port}"

    echo = EchoServer().start()
    udp_echo = UdpEchoServer().start()
    target = ("127.0.0.1", echo.port)
    udp_target = ("127.0.0.1", udp_echo.port)

    host = None
    npc = None
    try:
        print(f"npc binary : {npc_bin}")
        print(f"cargo      : {cargo_bin}")
        print(f"run dir    : {run_dir}")

        # ---------------- 0. build the interop host (once) ----------------
        # Build the libtest harness binary first; then run it directly for each
        # host instance. Running `cargo test` twice concurrently would deadlock
        # on cargo's build lock.
        print("\n-- building the Rust SOCKS5 interop host (cargo test --no-run)")
        build = subprocess.run(
            [
                str(cargo_bin), "test", "-p", "nps-server", "--test", "socks5",
                "--no-run", "--message-format=json",
            ],
            cwd=str(repo_root / "rust"),
            capture_output=True,
            text=True,
            timeout=args.build_timeout,
        )
        host_exe = None
        for line in build.stdout.splitlines():
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if (
                msg.get("reason") == "compiler-artifact"
                and msg.get("executable")
                and msg.get("target", {}).get("name") == "socks5"
            ):
                host_exe = msg["executable"]
        if host_exe is None:
            print("=" * 72)
            print("END-TO-END NOT EXECUTED: could not build the SOCKS5 host.")
            print(build.stderr[-8192:])
            print("=" * 72)
            return 3
        checks.ok("Rust SOCKS5 interop host built", host_exe)

        ready_file = run_dir / "host.ready"
        host_env = dict(os.environ)
        host_env.update(
            {
                "NPS_SOCKS5_IT_BRIDGE": bridge_addr,
                "NPS_SOCKS5_IT_VKEY": vkey,
                "NPS_SOCKS5_IT_LISTEN": socks_addr,
                "NPS_SOCKS5_IT_USERS": "",
                "NPS_SOCKS5_IT_READY": str(ready_file),
                "RUST_LOG": "info",
            }
        )
        host_argv = [host_exe, "--ignored", "--nocapture", "interop_host_for_real_npc"]
        host = spawn("socks5-host", host_argv, run_dir / "host.log",
                     env=host_env, cwd=repo_root / "rust")

        def host_ready() -> bool:
            ensure_alive(host)
            return ready_file.is_file() and ready_file.read_text().strip() != ""

        ok, err = wait_until(host_ready, args.build_timeout, interval=0.25)
        if not ok:
            print("=" * 72)
            print("END-TO-END NOT EXECUTED: SOCKS5 host did not come up.")
            print(f"  log: {host['log']}")
            print(tail(host["log"], 8192))
            print("=" * 72)
            return 3
        checks.ok("Rust SOCKS5 host started (bridge + SOCKS5 listener bound)")

        # ---------------- 1. real npc connects to the bridge ----------------
        npc_env = {k: v for k, v in os.environ.items() if k != "NPS_ADMIN_TOKEN"}
        print(f"\n-- starting REAL Go npc: {npc_bin}")
        npc_argv = [
            str(npc_bin),
            f"-server={bridge_addr}",
            f"-vkey={vkey}",
            "-type=tcp",
            "-log=stdout",
            "-log_level=7",
        ]
        npc = spawn("npc", npc_argv, run_dir / "npc.log", env=npc_env,
                    cwd=run_dir)

        # npc logs a successful mux/bridge connect; also probe with a real
        # SOCKS5 CONNECT and retry until the tunnel is usable.
        def socks_works() -> bool:
            ensure_alive(npc)
            try:
                c = connect_via_socks(
                    ("127.0.0.1", socks_port), target, atyp=ATYP_IPV4
                )
            except Exception:
                return False
            try:
                c.send(b"probe")
                got = c.recv_exactly(5)
                return got == b"probe"
            except Exception:
                return False
            finally:
                c.close()

        ok, err = wait_until(socks_works, args.online_timeout, interval=0.3)
        checks.expect(
            ok,
            "real Go npc registered; SOCKS5 CONNECT reaches the echo target",
            "" if ok else f"last error: {err}",
        )
        if not ok:
            raise SmokeFail("npc never became usable through the SOCKS5 proxy")

        # ---------------- 2. no-auth mode, byte-exact payloads --------------
        print("\n-- no-auth mode: byte-exact payloads")
        c = Socks5Client(("127.0.0.1", socks_port))
        method = c.negotiate(None)
        checks.expect(
            method == METHOD_NO_AUTH,
            "no-auth: server selects method 0x00 when no accounts configured",
            f"method=0x{method:02x}",
        )
        rep, bnd = c.request(CMD_CONNECT, ATYP_IPV4, target[0], target[1])
        checks.expect(rep == REP_SUCCEEDED, "no-auth: CONNECT reply REP=0", f"BND={bnd}")

        for size in (1, 9, 4096, 300 * KIB, 4 * MIB):
            payload = bytes((i * 37 + 11) & 0xFF for i in range(min(size, 4096)))
            if size > len(payload):
                payload = (payload * ((size // len(payload)) + 1))[:size]
            c.send(payload)
            got = c.recv_exactly(len(payload))
            checks.expect(
                got == payload,
                f"no-auth: {size} byte payload echoed byte-exactly",
                "" if got == payload else f"got {len(got)} bytes, mismatch",
            )
        c.close()

        # ---------------- 3. domain ATYP -----------------------------------
        print("\n-- domain ATYP (npc resolves 'localhost' itself)")
        c = Socks5Client(("127.0.0.1", socks_port))
        c.negotiate(None)
        rep, _ = c.request(CMD_CONNECT, ATYP_DOMAIN, "localhost", target[1])
        checks.expect(rep == REP_SUCCEEDED, "domain ATYP: CONNECT REP=0", f"rep={rep}")
        if rep == REP_SUCCEEDED:
            c.send(b"domain-target")
            checks.expect(
                c.recv_exactly(13) == b"domain-target",
                "domain ATYP: payload echoed byte-exactly",
            )
        c.close()

        # ---------------- 4. IPv4 ATYP is the default above; assert REP=0 ---
        # (covered) -- now negative cases.

        # ---------------- 5. BIND -> REP=7 ---------------------------------
        print("\n-- unsupported commands")
        c = Socks5Client(("127.0.0.1", socks_port))
        c.negotiate(None)
        rep, _ = c.request(CMD_BIND, ATYP_IPV4, "127.0.0.1", 0)
        checks.expect(
            rep == REP_COMMAND_NOT_SUPPORTED,
            "BIND returns REP=7 (command not supported), not a fake success",
            f"rep={rep}",
        )
        c.close()

        # ---------------- 6. unknown ATYP -> REP=8 -------------------------
        c = Socks5Client(("127.0.0.1", socks_port))
        c.negotiate(None)
        c.sock.sendall(bytes([VER, CMD_CONNECT, 0x00, 0x09]) + b"\x01\x02\x03\x04\x00\x50")
        rep, _ = c.read_reply()
        checks.expect(
            rep == REP_ADDRESS_TYPE_NOT_SUPPORTED,
            "unknown ATYP returns REP=8",
            f"rep={rep}",
        )
        c.close()

        # ---------------- 6b. UDP ASSOCIATE -------------------------------
        # Substream ConnType is "udp5"; the payload crossing it is the Go
        # SOCKS5 UDP datagram (`RSV(2) FRAG(1) ATYP ADDR PORT DATA`).
        # npc binds a local UDP socket, so a real datagram really reaches the
        # UDP echo target and comes back.
        print("\n-- UDP ASSOCIATE (substream ConnType=udp5)")
        c = Socks5Client(("127.0.0.1", socks_port))
        c.negotiate(None)
        rep, bnd = c.request(CMD_UDP_ASSOCIATE, ATYP_IPV4, "0.0.0.0", 0)
        checks.expect(
            rep == REP_SUCCEEDED and bnd[1] != 0,
            "UDP ASSOCIATE: REP=0 with a real BND port",
            f"BND={bnd}",
        )
        if rep == REP_SUCCEEDED:
            udp_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                udp_client.settimeout(10)
                payload = b"udp-associate-payload-7c1f"
                dgram = socks5_udp_header(
                    ATYP_IPV4, udp_target[0], udp_target[1]
                ) + payload
                udp_client.sendto(dgram, bnd)
                got, _src = udp_client.recvfrom(65535)
                checks.expect(
                    got == dgram,
                    "UDP ASSOCIATE: datagram reached the UDP echo target and returned intact",
                    "" if got == dgram else f"got {len(got)} bytes: {got[:40]!r}",
                )
                # 第二条报文：验证关联可以复用
                payload2 = b"second-datagram"
                dgram2 = socks5_udp_header(
                    ATYP_IPV4, udp_target[0], udp_target[1]
                ) + payload2
                udp_client.sendto(dgram2, bnd)
                got2, _ = udp_client.recvfrom(65535)
                checks.expect(
                    got2 == dgram2,
                    "UDP ASSOCIATE: association is reusable for a second datagram",
                )
            finally:
                udp_client.close()
        # 关闭 TCP 控制连接 → 关联结束
        c.close()
        time.sleep(0.2)

        # ---------------- 7. unreachable target ----------------------------
        # The legacy protocol has no dial-result frame: the server answers
        # REP=0 and npc closes the substream. We assert the observable
        # behaviour (no hang, no crash, immediate EOF) and report it as such.
        print("\n-- unreachable target (documented boundary)")
        c = Socks5Client(("127.0.0.1", socks_port))
        c.negotiate(None)
        rep, _ = c.request(CMD_CONNECT, ATYP_IPV4, "127.0.0.1", 1)
        checks.expect(
            rep == REP_SUCCEEDED,
            "unreachable target: server replies REP=0 (Go parity: no dial result in protocol)",
            f"rep={rep}",
        )
        if rep == REP_SUCCEEDED:
            c.send(b"x")
            try:
                c.sock.settimeout(10)
                got = c.sock.recv(16)
                closed = got == b""
            except (ConnectionError, OSError):
                closed = True
            checks.expect(
                closed,
                "unreachable target: connection closed promptly instead of hanging",
            )
        c.close()

        # ---------------- 8. auth mode ------------------------------------
        print("\n-- username/password mode (second host instance)")
        authed_addr = f"127.0.0.1:{authed_port}"
        user, password = "alice", "s3cret-pass-9f2c"
        ready2 = run_dir / "host-auth.ready"
        host2_env = dict(host_env)
        host2_env.update(
            {
                # 独立桥端口：第一个 host 仍占着 bridge_addr
                "NPS_SOCKS5_IT_BRIDGE": bridge2_addr,
                "NPS_SOCKS5_IT_LISTEN": authed_addr,
                "NPS_SOCKS5_IT_USERS": f"{user}:{password}",
                "NPS_SOCKS5_IT_READY": str(ready2),
            }
        )
        host2 = spawn(
            "socks5-host-auth",
            host_argv,
            run_dir / "host-auth.log",
            env=host2_env,
            cwd=repo_root / "rust",
        )
        try:
            ok, err = wait_until(
                lambda: (ensure_alive(host2), ready2.is_file())[1],
                args.build_timeout,
                interval=0.25,
            )
            if not ok:
                raise SmokeFail(f"auth host did not start: {err}\n{tail(host2['log'])}")

            # 第二个 npc 连到第二个桥（认证模式的 SOCKS5 需要它才能建流）
            npc2 = spawn(
                "npc-auth",
                [
                    str(npc_bin), f"-server={bridge2_addr}", f"-vkey={vkey}",
                    "-type=tcp", "-log=stdout", "-log_level=7",
                ],
                run_dir / "npc-auth.log",
                env=npc_env,
                cwd=run_dir,
            )
            try:

                def auth_socks_works() -> bool:
                    ensure_alive(npc2)
                    try:
                        cc = connect_via_socks(
                            ("127.0.0.1", authed_port), target,
                            credentials=(user, password), atyp=ATYP_IPV4,
                        )
                    except Exception:
                        return False
                    try:
                        cc.send(b"probe")
                        return cc.recv_exactly(5) == b"probe"
                    except Exception:
                        return False
                    finally:
                        cc.close()

                ok2, err2 = wait_until(auth_socks_works, args.online_timeout, interval=0.3)
                checks.expect(
                    ok2,
                    "auth: real npc registered on the second bridge",
                    "" if ok2 else f"last error: {err2}",
                )
                if not ok2:
                    raise SmokeFail("npc (auth host) never became usable")

                # 8a. correct credentials
                c = Socks5Client(("127.0.0.1", authed_port))
                method = c.negotiate((user, password))
                checks.expect(
                    method == METHOD_USERPASS,
                    "auth: server selects method 0x02 when accounts are configured",
                    f"method=0x{method:02x}",
                )
                rep, _ = c.request(CMD_CONNECT, ATYP_IPV4, target[0], target[1])
                checks.expect(rep == REP_SUCCEEDED, "auth: CONNECT with valid credentials")
                if rep == REP_SUCCEEDED:
                    blob = b"authenticated-payload"
                    c.send(blob)
                    checks.expect(
                        c.recv_exactly(len(blob)) == blob,
                        "auth: payload echoed byte-exactly",
                    )
                c.close()

                # 8b. wrong password -> STATUS=1 and connection closed
                c = Socks5Client(("127.0.0.1", authed_port))
                method, status = c.auth_only_raw(user, "definitely-wrong")
                checks.expect(
                    method == METHOD_USERPASS and status == 1,
                    "auth: wrong password rejected with STATUS=1",
                    f"method=0x{method:02x} status={status}",
                )
                try:
                    c.sock.settimeout(5)
                    leftover = c.sock.recv(16)
                    closed = leftover == b""
                except (ConnectionError, OSError):
                    closed = True
                checks.expect(closed, "auth: connection closed immediately after failure")
                c.close()

                # 8c. unknown user
                c = Socks5Client(("127.0.0.1", authed_port))
                method, status = c.auth_only_raw("nobody", password)
                checks.expect(
                    method == METHOD_USERPASS and status == 1,
                    "auth: unknown username rejected with STATUS=1",
                    f"status={status}",
                )
                c.close()

                # 8d. offering only no-auth must be refused (0xFF)
                c = Socks5Client(("127.0.0.1", authed_port))
                c.sock.sendall(bytes([VER, 1, METHOD_NO_AUTH]))
                ver, method = recv_exact(c.sock, 2)
                checks.expect(
                    ver == VER and method == METHOD_NONE_ACCEPTABLE,
                    "auth: server refuses a no-auth-only greeting with 0xFF",
                    f"method=0x{method:02x}",
                )
                c.close()

                # 8e. no credential leak in logs
                logs = (run_dir / "host-auth.log").read_text(encoding="utf-8", errors="replace")
                checks.expect(
                    password not in logs,
                    "auth: password never appears in server logs",
                )

            finally:
                stop_proc(npc2)
        finally:
            stop_proc(host2)

        # ---------------- 9. npc log sanity --------------------------------
        npc_log = (run_dir / "npc.log").read_text(encoding="utf-8", errors="replace")
        checks.expect(
            "connect to server" in npc_log.lower()
            or "successful" in npc_log.lower()
            or "connection" in npc_log.lower(),
            "npc log shows a successful bridge connection",
        )

        # ---------------- summary -----------------------------------------
        print("\n" + "=" * 72)
        print(f"checks: {checks.passed} passed, {checks.failed} failed")
        if checks.failed:
            print("\nfailures:")
            for f in checks.failures:
                print(f"  - {f}")
            print(f"\nlogs kept in: {run_dir}")
            return 1
        print(f"all checks passed; logs in: {run_dir}")
        return 0

    except SmokeFail as e:
        print(f"\nSMOKE FAILURE: {e}", file=sys.stderr)
        if npc:
            print("\n--- npc log tail ---", file=sys.stderr)
            print(tail(npc["log"]), file=sys.stderr)
        if host:
            print("\n--- host log tail ---", file=sys.stderr)
            print(tail(host["log"]), file=sys.stderr)
        print(f"\nlogs kept in: {run_dir}", file=sys.stderr)
        return 1
    except Exception:
        traceback.print_exc()
        if npc:
            print("\n--- npc log tail ---", file=sys.stderr)
            print(tail(npc["log"]), file=sys.stderr)
        if host:
            print("\n--- host log tail ---", file=sys.stderr)
            print(tail(host["log"]), file=sys.stderr)
        return 1
    finally:
        stop_proc(npc)
        stop_proc(host)
        echo.stop()
        udp_echo.stop()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Real Go npc <-> Rust SOCKS5 interop smoke test",
    )
    p.add_argument("--cargo-bin", default=None, help="path to cargo(.exe)")
    p.add_argument("--npc-bin", default=None, help="path to the real npc(.exe)")
    p.add_argument("--online-timeout", type=float, default=40.0,
                   help="seconds to wait for npc to become usable (default 40)")
    p.add_argument("--build-timeout", type=float, default=240.0,
                   help="seconds to wait for the Rust host to build+start (default 240)")
    return run(p.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
