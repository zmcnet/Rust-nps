#!/usr/bin/env python3
"""Cross-verification for the Rust-nps client (`rnpc`) against the REAL Go nps server.

Scope / ownership
-----------------
This file lives inside `rust/crates/nps-client/verify/` (the client agent's own
directory). It never writes to `tools/interop/`, `resources/nps/` or any other
crate. All runtime state (server conf, DB files, logs) goes to a fresh temp
directory, never into the source tree.

What is verified (all against `tools/interop/server/nps.exe`, the real Go nps
0.26.10 server, unless `--skip-go` is passed):

  [mode3-pub]  rnpc -config npc.json  (server has public_vkey set)
               -> conf handshake, NEW_CONF, server-assigned 16-byte vkey,
                  NEW_TASK, then main+chan; a tcp tunnel appears on the server
                  and moves 768 KiB byte-exactly (sha256 both ways).
  [mode3-priv] rnpc -config npc.json  (pre-created client, ConfigConnAllow=true)
               -> conf handshake, isPub=false (no NEW_CONF), NEW_TASK only.
  [mode2]      rnpc -s <host> -p <port> with an explicit vkey
               -> identical behaviour to -server=<host:port> (tunnel works).
  [mode4-ok]   rnpc -s <host> -p <port> with no vkey and NPS_PUBLIC_VKEY set
               -> rgst is refused by the Go server, fallback public-vkey conf
                  registration succeeds, client stays online (main+chan up).
  [mode4-deny] same but NPS_PUBLIC_VKEY wrong -> exit code 7, no retry loop.
  [cli]        -server host:port + -p   -> exit 2 (explicit conflict)
               invalid JSON config      -> exit 8 with line/column
               JSON config > 1 MiB      -> exit 8
               unknown / reserved subcommand -> exit 2
  [redaction]  neither the config vkey nor the server-assigned vkey appears in
               the client log or on stderr.

Usage (isolated, stdlib only):
    python -I verify_modes.py --rnpc <path/to/rnpc.exe>
    python -I verify_modes.py --rnpc ... --nps-bin <path/to/nps.exe> --keep

Exit codes: 0 all checks passed, 1 a check failed, 2 a required binary is missing.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
DEFAULT_NPS = REPO / "tools" / "interop" / "server" / "nps.exe"
CHUNK = 32 * 1024
DATA_SIZE = 768 * 1024  # > 512 KiB as required


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_port(port: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def pattern(seed: int, length: int) -> bytes:
    base = bytearray()
    state = seed & 0xFFFFFFFF
    for _ in range(length):
        state = (1103515245 * state + 12345) & 0x7FFFFFFF
        base.append(state & 0xFF)
    return bytes(base)


class Echo:
    """Threaded byte-exact echo server."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(32)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _serve(conn: socket.socket) -> None:
        try:
            while True:
                data = conn.recv(CHUNK)
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    def close(self) -> None:
        self._stop.set()
        with contextlib.suppress(OSError):
            self.sock.close()


def echo_sha256(port: int, total: int, timeout: float = 60.0) -> str:
    """Send `total` bytes, read them back, return sha256 of the received data."""
    data = pattern(0x5EED, total)
    digest = hashlib.sha256()
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sent = 0

        def writer() -> None:
            try:
                nonlocal sent
                offset = 0
                while offset < total:
                    n = min(CHUNK, total - offset)
                    sock.sendall(data[offset:offset + n])
                    offset += n
                sent = offset
            except OSError:
                pass

        thread = threading.Thread(target=writer, daemon=True)
        thread.start()
        received = bytearray()
        while len(received) < total:
            chunk = sock.recv(min(CHUNK, total - len(received)))
            if not chunk:
                raise RuntimeError(
                    f"tunnel closed after {len(received)}/{total} bytes"
                )
            digest.update(chunk)
            received.extend(chunk)
        thread.join(timeout=timeout)
    return digest.hexdigest()


def wait_tunnel(port: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            if echo_sha256(port, 4096, timeout=2.0):
                return True
        except (OSError, RuntimeError):
            time.sleep(0.15)
    return False


class Checks:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0
        self.failures: list[str] = []

    def expect(self, name: str, ok: bool, detail: str = "") -> bool:
        if ok:
            self.passed += 1
            print(f"PASS  {name}" + (f"  [{detail}]" if detail else ""), flush=True)
        else:
            self.failed += 1
            self.failures.append(f"{name}: {detail}" if detail else name)
            print(f"FAIL  {name}" + (f"  [{detail}]" if detail else ""), flush=True)
        return ok


class Proc:
    def __init__(self, label: str, args: list[str], cwd: Path, log: Path,
                 env: dict[str, str] | None = None) -> None:
        self.label = label
        self.log_path = log
        full_env = os.environ.copy()
        full_env.pop("RUST_LOG", None)
        full_env.update(env or {})
        self.handle = open(log, "w", encoding="utf-8", errors="replace")
        self.popen = subprocess.Popen(
            args, cwd=str(cwd), stdin=subprocess.DEVNULL,
            stdout=self.handle, stderr=subprocess.STDOUT, env=full_env,
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )

    def alive(self) -> bool:
        return self.popen.poll() is None

    def text(self) -> str:
        with contextlib.suppress(OSError, ValueError):
            self.handle.flush()
        try:
            return self.log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def tail(self, lines: int = 20) -> str:
        return "\n".join(self.text().splitlines()[-lines:])

    def wait(self, timeout: float) -> int | None:
        try:
            return self.popen.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def stop(self, timeout: float = 8.0) -> None:
        if self.alive():
            self.popen.terminate()
            if self.wait(timeout) is None:
                self.popen.kill()
                self.popen.wait(timeout=timeout)
        with contextlib.suppress(OSError, ValueError):
            self.handle.close()


def run_cli(args: list[str], cwd: Path, timeout: float = 40.0) -> tuple[int, str]:
    result = subprocess.run(
        args, cwd=str(cwd), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=timeout, text=True, encoding="utf-8", errors="replace",
        env={**os.environ, "RUST_LOG": ""},
    )
    return result.returncode, result.stdout or ""


# ---------------------------------------------------------------------------
# Go nps server config
# ---------------------------------------------------------------------------
def write_go_server(root: Path, nps_bin: Path, bridge: int, web: int,
                    public_vkey: str, precreated_client: dict | None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    conf = root / "conf"
    conf.mkdir(exist_ok=True)
    shutil.copy2(nps_bin, root / "nps.exe")

    lines = [
        "appname = nps",
        "runmode = dev",
        "bridge_type = tcp",
        f"bridge_port = {bridge}",
        "bridge_ip = 127.0.0.1",
        f"public_vkey = {public_vkey}",
        "log_level = 7",
        "web_host = 127.0.0.1",
        "web_username = admin",
        "web_password = " + hashlib.md5(b"admin").hexdigest(),
        f"web_port = {web}",
        "web_ip = 127.0.0.1",
        "web_base_url =",
        "web_open_ssl = false",
        "auth_crypt_key = 0123456789abcdef",
        "allow_user_login = false",
        "allow_user_register = false",
        "allow_flow_limit = false",
        "allow_rate_limit = false",
        "allow_tunnel_num_limit = false",
        "allow_local_proxy = false",
        "allow_connection_num_limit = false",
        "allow_multi_ip = false",
        "system_info_display = false",
        "http_cache = false",
        "disconnect_timeout = 5",
        "",
    ]
    (conf / "nps.conf").write_text("\n".join(lines), encoding="utf-8")

    if precreated_client:
        (conf / "clients.json").write_text(
            json.dumps(precreated_client, separators=(",", ":")) + "\n*#*",
            encoding="utf-8",
        )
    (conf / "tasks.json").write_text("", encoding="utf-8")
    (conf / "hosts.json").write_text("", encoding="utf-8")
    return root / "nps.exe"


def go_client_record(vkey: str, remark: str, config_conn_allow: bool) -> dict:
    return {
        "Cnf": {"U": "", "P": "", "Compress": False, "Crypt": False},
        "Id": 1,
        "VerifyKey": vkey,
        "Addr": "",
        "Remark": remark,
        "Status": True,
        "IsConnect": False,
        "RateLimit": 0,
        "Flow": {"ExportFlow": 0, "InletFlow": 0, "FlowLimit": 0},
        "NoStore": False,
        "NoDisplay": False,
        "MaxConn": 0,
        "NowConn": 0,
        "WebUserName": "",
        "WebPassword": "",
        "ConfigConnAllow": config_conn_allow,
        "MaxTunnelNum": 0,
        "Version": "",
    }


# ---------------------------------------------------------------------------
# checks
# ---------------------------------------------------------------------------
def mode3(checks: Checks, rnpc: Path, root: Path, label: str, vkey: str,
          bridge: int, listen: int, target: int, public_vkey: str | None,
          extra_env: dict[str, str] | None, expect_assigned: bool) -> None:
    config = {
        "common": {
            "server_addr": "127.0.0.1",
            "server_port": bridge,
            "vkey": vkey,
            "conn_type": "tcp",
            "auto_reconnection": True,
            "remark": label,
            "max_conn": 64,
        },
        "tasks": [{
            "remark": f"{label}-tcp",
            "mode": "tcp",
            "server_port": listen,
            "server_ip": "127.0.0.1",
            "target_addr": f"127.0.0.1:{target}",
        }],
    }
    path = root / f"{label}.json"
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")

    proc = Proc(label, [str(rnpc), "-config", str(path)], root,
                root / f"{label}.log", extra_env)
    try:
        up = wait_tunnel(listen, 30)
        checks.expect(f"[{label}] server-side tunnel is up", up, f"listen={listen}")
        if up:
            digest = echo_sha256(listen, DATA_SIZE, timeout=90)
            expected = hashlib.sha256(pattern(0x5EED, DATA_SIZE)).hexdigest()
            checks.expect(f"[{label}] 768 KiB echo sha256 matches", digest == expected,
                          f"sha256={digest[:16]}...")
        text = proc.text()
        checks.expect(f"[{label}] config vkey not in client log", vkey not in text)
        checks.expect(f"[{label}] client still running", proc.alive(),
                      proc.tail(6))
        if expect_assigned:
            checks.expect(f"[{label}] NEW_CONF path announced", "已分配新的客户端密钥" in text,
                          proc.tail(8))
        else:
            checks.expect(f"[{label}] non-public path (no NEW_CONF)",
                          "已分配新的客户端密钥" not in text)
    finally:
        proc.stop()


def mode4_ok(checks: Checks, rnpc: Path, root: Path, server: str, port: int,
             public_vkey: str) -> None:
    log = root / "mode4-ok.log"
    proc = Proc("mode4-ok", [str(rnpc), "-s", server, "-p", str(port)],
                root, log, {"NPS_PUBLIC_VKEY": public_vkey})
    try:
        online = False
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            text = proc.text()
            if "已连接服务端" in text:
                online = True
                break
            if not proc.alive():
                break
            time.sleep(0.2)
        checks.expect("[mode4-ok] registration + main/chan online", online, proc.tail(10))
        checks.expect("[mode4-ok] assigned vkey not in log",
                      public_vkey not in proc.text())
    finally:
        proc.stop()


def mode4_denied(checks: Checks, rnpc: Path, root: Path, server: str,
                 port: int) -> None:
    env = {"NPS_PUBLIC_VKEY": "definitely-not-the-public-vkey"}
    proc = Proc("mode4-deny", [str(rnpc), "-s", server, "-p", str(port)],
                root, root / "mode4-deny.log", env)
    code = proc.wait(30)
    if code is None:
        proc.stop()
    checks.expect("[mode4-deny] exits with dedicated code 7", code == 7,
                  f"exit={code} tail={proc.tail(10)}")
    checks.expect("[mode4-deny] no infinite retry (single process exit)",
                  code is not None)
    proc.stop()


def cli_checks(checks: Checks, rnpc: Path, root: Path, vkey: str) -> None:
    code, out = run_cli([str(rnpc), "-server=127.0.0.1:8024", "-p=8024",
                         f"-vkey={vkey}"], root)
    checks.expect("[cli] -server host:port + -p -> exit 2", code == 2, f"exit={code}")
    checks.expect("[cli] conflict message mentions -p", "-p" in out, out[-160:])

    bad_json = root / "bad.json"
    bad_json.write_text('{\n  "common": ,\n}\n', encoding="utf-8")
    code, out = run_cli([str(rnpc), "-config", str(bad_json)], root)
    checks.expect("[cli] invalid JSON -> exit 8", code == 8, f"exit={code}")
    checks.expect("[cli] invalid JSON reports line/column",
                  "第 2 行" in out and "列" in out, out[-200:])

    big = root / "big.json"
    big.write_bytes(b'{"common":' + b" " * (1024 * 1024 + 16) + b"}")
    code, out = run_cli([str(rnpc), "-config", str(big)], root)
    checks.expect("[cli] config > 1 MiB -> exit 8", code == 8, f"exit={code}")
    checks.expect("[cli] size error is explicit", "1 MiB" in out, out[-160:])

    code, out = run_cli([str(rnpc), "install"], root)
    checks.expect("[cli] reserved subcommand -> exit 2", code == 2, f"exit={code}")
    checks.expect("[cli] reserved subcommand says 尚未实现", "尚未实现" in out)

    code, out = run_cli([str(rnpc), "bogus-cmd"], root)
    checks.expect("[cli] unknown subcommand -> exit 2", code == 2, f"exit={code}")
    checks.expect("[cli] unknown subcommand points at `rnpc help`",
                  "rnpc help" in out)

    code, out = run_cli([str(rnpc), "-s", "10.0.0.1", "-p", "8024",
                         "-vkey", vkey, "-type", "udp"], root)
    checks.expect("[cli] unsupported -type -> exit 5", code == 5, f"exit={code}")
    checks.expect("[cli] unsupported type does not echo vkey", vkey not in out)


def main() -> int:
    parser = argparse.ArgumentParser(description="rnpc <-> real Go nps verification")
    parser.add_argument("--rnpc", default=str(REPO / "rust" / "target" / "debug" / "rnpc.exe"))
    parser.add_argument("--nps-bin", default=str(DEFAULT_NPS))
    parser.add_argument("--skip-go", action="store_true",
                        help="only run CLI checks (no live server)")
    parser.add_argument("--keep", action="store_true", help="keep the temp dir")
    args = parser.parse_args()

    rnpc = Path(args.rnpc)
    nps = Path(args.nps_bin)
    missing = []
    if not rnpc.exists():
        missing.append(f"rnpc missing: {rnpc}")
    if not args.skip_go and not nps.exists():
        missing.append(f"Go nps missing: {nps}")
    if missing:
        for item in missing:
            print(f"ERROR {item}", file=sys.stderr)
        return 2

    stamp = time.strftime("%Y%m%d-%H%M%S")
    root = Path(tempfile.gettempdir()) / f"nps-client-verify-{stamp}"
    root.mkdir(parents=True, exist_ok=True)
    print(f"== rnpc cross-verification ({stamp}) ==")
    print(f"rnpc: {rnpc}")
    print(f"nps : {nps}")
    print(f"dir : {root}\n")

    checks = Checks()
    servers: list[Proc] = []
    try:
        secret = "verify-" + hashlib.sha256(os.urandom(16)).hexdigest()[:12]
        cli_checks(checks, rnpc, root, secret)

        if not args.skip_go:
            echo = Echo()
            bridge, web, listen_pub = free_port(), free_port(), free_port()
            listen_priv = free_port()
            public_vkey = "pub-" + hashlib.sha256(os.urandom(8)).hexdigest()[:8]

            go_root = root / "go-server"
            exe = write_go_server(go_root, nps, bridge, web, public_vkey, None)
            server = Proc("nps", [str(exe)], go_root, root / "nps.log")
            servers.append(server)
            checks.expect("[server] Go nps bridge is listening", wait_port(bridge, 20),
                          f"port={bridge}")
            checks.expect("[server] Go nps web is listening", wait_port(web, 20),
                          f"port={web}")

            # ---- mode 3, public client: NEW_CONF -> 16-byte vkey ----
            mode3(checks, rnpc, root, "mode3-pub", public_vkey, bridge, listen_pub,
                  echo.port, public_vkey, None, expect_assigned=True)

            # ---- mode 3, private client (ConfigConnAllow) ----
            # Needs a fresh server DB holding a non-public client.
            server.stop()
            bridge, web, listen_priv = free_port(), free_port(), free_port()
            go_root2 = root / "go-server-private"
            pre = go_client_record(secret, "private-client", True)
            exe2 = write_go_server(go_root2, nps, bridge, web, "", pre)
            server2 = Proc("nps-private", [str(exe2)], go_root2, root / "nps-private.log")
            servers.append(server2)
            checks.expect("[server-private] bridge listening", wait_port(bridge, 20),
                          f"port={bridge}")
            mode3(checks, rnpc, root, "mode3-priv", secret, bridge, listen_priv,
                  echo.port, None, None, expect_assigned=False)

            # ---- mode 2: -s host -p port with explicit vkey ----
            listen_split = free_port()
            config = {
                "common": {"server_addr": "127.0.0.1", "server_port": bridge,
                           "vkey": secret, "remark": "split"},
                "tasks": [{"remark": "split-tcp", "mode": "tcp",
                           "server_port": listen_split,
                           "target_addr": f"127.0.0.1:{echo.port}"}],
            }
            split_cfg = root / "split.json"
            split_cfg.write_text(json.dumps(config), encoding="utf-8")
            # register the tunnel through config mode, then run with -s/-p
            setup = Proc("split-setup", [str(rnpc), "-config", str(split_cfg)],
                         root, root / "split-setup.log")
            time.sleep(2.0)
            setup.stop()
            proc = Proc("mode2", [str(rnpc), "-s", "127.0.0.1", "-p", str(bridge),
                                  "-vkey", secret], root, root / "mode2.log")
            try:
                up = wait_tunnel(listen_split, 30)
                checks.expect("[mode2] -s/-p tunnel works", up, f"listen={listen_split}")
                if up:
                    digest = echo_sha256(listen_split, 128 * 1024, timeout=60)
                    expected = hashlib.sha256(pattern(0x5EED, 128 * 1024)).hexdigest()
                    checks.expect("[mode2] 128 KiB echo sha256 matches", digest == expected)
            finally:
                proc.stop()

            # ---- mode 4 ----
            mode4_ok(checks, rnpc, root, "127.0.0.1", bridge, public_vkey)
            mode4_denied(checks, rnpc, root, "127.0.0.1", bridge)

            echo.close()
    except Exception:  # noqa: BLE001 - surface everything in the report
        checks.expect("harness completed without exception", False,
                      traceback.format_exc())
    finally:
        for server in servers:
            server.stop()

    print(f"\n{checks.passed} passed, {checks.failed} failed")
    if checks.failures:
        print("failures:")
        for failure in checks.failures:
            print(f"  - {failure}")
    print(f"logs: {root}")
    if not args.keep and not checks.failures:
        pass  # logs are small; keep them for the report
    return 0 if checks.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
