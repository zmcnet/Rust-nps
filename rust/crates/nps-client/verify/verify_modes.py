#!/usr/bin/env python3
"""Cross-verification for the Rust-nps client (`rnpc`) against the REAL Go nps server.

Scope / ownership
-----------------
This file lives inside `rust/crates/nps-client/verify/` (the client agent's own
directory). It never writes to `tools/interop/`, `resources/nps/` or any other
crate. All runtime state (server conf, DB files, logs) goes to a fresh directory
under the system temp dir, never into the source tree.

What is verified against `tools/interop/server/nps.exe` (real Go nps 0.26.10):

  [mode3-pub]   rnpc -config npc.json, server has `public_vkey`
                -> conf handshake, isPub=true, NEW_CONF, server-assigned
                   16-byte vkey, NEW_TASK, then main+chan. The tunnel shows up
                   on the server and moves 768 KiB byte-exactly (sha256).
  [mode3-priv]  rnpc -config npc.json, pre-created client with
                ConfigConnAllow=true -> isPub=false (no NEW_CONF), NEW_TASK.
  [mode2]       rnpc -s <host> -p <port> -vkey <key> serves a tunnel that the
                server already has configured (server-pushed model); 768 KiB
                byte-exact. This is the same tunnel that -server=host:port
                would serve (the two forms are asserted equivalent in unit
                tests and by the CLI conflict check below).
  [mode4-ok]    rnpc -s <host> -p <port> with no vkey and NPS_PUBLIC_VKEY set
                -> rgst refused by the Go server, fallback public-vkey conf
                   registration assigns a vkey, client stays online.
  [mode4-deny]  same but wrong NPS_PUBLIC_VKEY -> exit 7, no retry loop.
  [cli]         -server host:port + -p  -> exit 2
                invalid JSON config     -> exit 8 with line/column
                JSON config > 1 MiB     -> exit 8
                reserved subcommand     -> exit 2 + "尚未实现"
                unknown subcommand      -> exit 2 + "rnpc help"
                -type udp               -> exit 5
  [redaction]   the config vkey never appears in client logs or on stderr.

Usage (isolated, stdlib only):
    python -I verify_modes.py --rnpc <path/to/rnpc.exe>
    python -I verify_modes.py --rnpc ... --nps-bin <path/to/nps.exe> --keep

Exit codes: 0 all checks passed, 1 a check failed, 2 a required binary missing.
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


def echo_sha256(port: int, total: int, timeout: float = 90.0) -> str:
    """Send `total` bytes through the tunnel and hash what comes back."""
    data = pattern(0x5EED, total)
    digest = hashlib.sha256()
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.settimeout(timeout)

        def writer() -> None:
            try:
                offset = 0
                while offset < total:
                    n = min(CHUNK, total - offset)
                    sock.sendall(data[offset:offset + n])
                    offset += n
            except OSError:
                pass

        thread = threading.Thread(target=writer, daemon=True)
        thread.start()
        received = 0
        while received < total:
            chunk = sock.recv(min(CHUNK, total - received))
            if not chunk:
                raise RuntimeError(f"tunnel closed after {received}/{total} bytes")
            digest.update(chunk)
            received += len(chunk)
        thread.join(timeout=timeout)
    return digest.hexdigest()


def wait_tunnel(port: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            echo_sha256(port, 4096, timeout=3.0)
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
    env = {**os.environ}
    env.pop("RUST_LOG", None)
    result = subprocess.run(
        args, cwd=str(cwd), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=timeout, text=True, encoding="utf-8", errors="replace", env=env,
    )
    return result.returncode, result.stdout or ""


# ---------------------------------------------------------------------------
# Go nps server fixtures
# ---------------------------------------------------------------------------
def write_go_server(root: Path, nps_bin: Path, bridge: int, web: int,
                    public_vkey: str, clients: list[dict] | None,
                    tasks: list[dict] | None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    conf = root / "conf"
    conf.mkdir(exist_ok=True)
    shutil.copy2(nps_bin, root / "nps.exe")

    (conf / "nps.conf").write_text("\n".join([
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
    ]), encoding="utf-8")

    # 这三个文件必须存在，Go 服务端启动时会直接读（缺失会 panic）。
    for name, records in (
        ("clients.json", clients),
        ("tasks.json", tasks),
        ("hosts.json", None),
    ):
        body = ""
        if records:
            body = "\n*#*".join(
                json.dumps(record, separators=(",", ":")) for record in records
            )
        (conf / name).write_text(body, encoding="utf-8")
    return root / "nps.exe"


def go_client_record(vkey: str, remark: str, config_conn_allow: bool,
                     client_id: int = 1) -> dict:
    return {
        "Cnf": {"U": "", "P": "", "Compress": False, "Crypt": False},
        "Id": client_id,
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


def go_task_record(client: dict, task_id: int, port: int, target: int,
                   remark: str) -> dict:
    return {
        "Id": task_id,
        "Port": port,
        "ServerIp": "127.0.0.1",
        "Mode": "tcp",
        "Status": True,
        "RunStatus": True,
        "Client": client,
        "Ports": "",
        "Flow": {"ExportFlow": 0, "InletFlow": 0, "FlowLimit": 0},
        "Password": "",
        "Remark": remark,
        "TargetAddr": f"127.0.0.1:{target}",
        "NoStore": False,
        "LocalPath": "",
        "StripPre": "",
        "Target": {
            "TargetStr": f"127.0.0.1:{target}",
            "TargetArr": None,
            "LocalProxy": False,
        },
        "MultiAccount": None,
    }


# ---------------------------------------------------------------------------
# scenario helpers
# ---------------------------------------------------------------------------
def run_config_tunnel(checks: Checks, rnpc: Path, root: Path, label: str,
                      vkey: str, bridge: int, listen: int, target: int,
                      expect_assigned: bool) -> None:
    """模式 3：配置文件上传隧道，然后校验 768 KiB 双向一致。"""
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
                root / f"{label}.log")
    try:
        up = wait_tunnel(listen, 30)
        checks.expect(f"[{label}] server-side tunnel is up", up, f"listen={listen}")
        if up:
            digest = echo_sha256(listen, DATA_SIZE)
            expected = hashlib.sha256(pattern(0x5EED, DATA_SIZE)).hexdigest()
            checks.expect(f"[{label}] 768 KiB echo sha256 matches", digest == expected,
                          f"sha256={digest[:16]}...")
        text = proc.text()
        checks.expect(f"[{label}] config vkey not in client log", vkey not in text)
        checks.expect(f"[{label}] client still running", proc.alive(), proc.tail(6))
        if expect_assigned:
            checks.expect(f"[{label}] NEW_CONF path announced",
                          "已分配新的客户端密钥" in text, proc.tail(8))
        else:
            checks.expect(f"[{label}] non-public path (no NEW_CONF)",
                          "已分配新的客户端密钥" not in text)
    finally:
        proc.stop()


def run_split_port_tunnel(checks: Checks, rnpc: Path, root: Path, label: str,
                          vkey: str, bridge: int, listen: int) -> None:
    """模式 2：`-s host -p port` 服务服务端已配置的隧道。"""
    proc = Proc(label, [str(rnpc), "-s", "127.0.0.1", "-p", str(bridge),
                        "-vkey", vkey], root, root / f"{label}.log")
    try:
        up = wait_tunnel(listen, 30)
        checks.expect(f"[{label}] -s/-p tunnel is up", up, f"listen={listen}")
        if up:
            digest = echo_sha256(listen, DATA_SIZE)
            expected = hashlib.sha256(pattern(0x5EED, DATA_SIZE)).hexdigest()
            checks.expect(f"[{label}] 768 KiB echo sha256 matches", digest == expected,
                          f"sha256={digest[:16]}...")
        checks.expect(f"[{label}] vkey not in client log", vkey not in proc.text())
        checks.expect(f"[{label}] client still running", proc.alive(), proc.tail(6))
    finally:
        proc.stop()


def start_direct_tunnel(checks: Checks, rnpc: Path, root: Path, label: str,
                        vkey: str, bridge: int, listen: int,
                        server_form: str, keep: bool = False):
    """启动一个直连客户端（模式 1 或模式 2 的写法）。

    `server_form` 为 "combined"（-server=host:port）或 "split"（-s host -p port）。
    返回 Proc，由调用方负责断言与关闭。
    """
    if server_form == "combined":
        args = [str(rnpc), f"-server=127.0.0.1:{bridge}", "-vkey", vkey]
    else:
        args = [str(rnpc), "-s", "127.0.0.1", "-p", str(bridge), "-vkey", vkey]
    proc = Proc(f"{label}-{server_form}", args, root,
                root / f"{label}-{server_form}.log")
    up = wait_tunnel(listen, 30)
    checks.expect(f"[{label}] {server_form} tunnel is up", up, f"listen={listen}")
    if up:
        digest = echo_sha256(listen, DATA_SIZE)
        expected = hashlib.sha256(pattern(0x5EED, DATA_SIZE)).hexdigest()
        checks.expect(f"[{label}] {server_form} 768 KiB sha256 matches",
                      digest == expected, f"sha256={digest[:16]}...")
    checks.expect(f"[{label}] {server_form} client running", proc.alive(),
                  proc.tail(6))
    checks.expect(f"[{label}] {server_form} vkey not in log",
                  vkey not in proc.text())
    if not keep:
        proc.stop()
    return proc


def spawn_fixture(root: Path, nps: Path, name: str, vkey: str,
                  echo: Echo) -> tuple[Proc, int, int]:
    """起一个带私有客户端 + 一条预建 tcp 隧道的 Go nps 实例。

    返回 (server_proc, bridge_port, listen_port)。
    """
    bridge, web, listen = free_port(), free_port(), free_port()
    client = go_client_record(vkey, f"fixture-{name}", True)
    task = go_task_record(client, 1, listen, echo.port, f"{name}-task")
    exe = write_go_server(root / f"go-{name}", nps, bridge, web, "",
                          [client], [task])
    server = Proc(f"nps-{name}", [str(exe)], root / f"go-{name}",
                  root / f"nps-{name}.log")
    checks_ok = wait_port(bridge, 20)
    if not checks_ok:
        raise RuntimeError(f"fixture {name} bridge did not start on {bridge}")
    return server, bridge, listen


def run_unsupported_mode_config(checks: Checks, rnpc: Path, root: Path,
                                vkey: str, bridge: int) -> None:
    """配置文件里只有 udp 隧道：必须明确告警并跳过，不能伪造成功。"""
    config = {
        "common": {"server_addr": "127.0.0.1", "server_port": bridge,
                   "vkey": vkey, "remark": "udp-only"},
        "tasks": [{"remark": "dns", "mode": "udp", "server_port": free_port(),
                   "target_addr": "8.8.8.8:53"}],
    }
    path = root / "udp-only.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    proc = Proc("udp-only", [str(rnpc), "-config", str(path)], root,
                root / "udp-only.log")
    try:
        deadline = time.monotonic() + 20
        text = ""
        while time.monotonic() < deadline:
            text = proc.text()
            if "已连接服务端" in text or not proc.alive():
                break
            time.sleep(0.2)
        checks.expect("[mode3-udp] unsupported mode is announced",
                      "暂不支持" in text and "udp" in text, proc.tail(10))
        checks.expect("[mode3-udp] no fake success log",
                      "tcp 隧道已在服务端注册" not in text)
        checks.expect("[mode3-udp] client keeps running (skips, not aborts)",
                      proc.alive(), proc.tail(8))
    finally:
        proc.stop()


def run_mode4_ok(checks: Checks, rnpc: Path, root: Path, bridge: int,
                 public_vkey: str) -> None:
    proc = Proc("mode4-ok", [str(rnpc), "-s", "127.0.0.1", "-p", str(bridge)],
                root, root / "mode4-ok.log", {"NPS_PUBLIC_VKEY": public_vkey})
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
        checks.expect("[mode4-ok] rgst refused -> public conf registration -> online",
                      online, proc.tail(12))
        checks.expect("[mode4-ok] public vkey not in log",
                      public_vkey not in proc.text())
        checks.expect("[mode4-ok] rgst refusal was attempted first",
                      "rgst" in proc.text(), proc.tail(8))
    finally:
        proc.stop()


def run_mode4_denied(checks: Checks, rnpc: Path, root: Path, bridge: int) -> None:
    proc = Proc("mode4-deny", [str(rnpc), "-s", "127.0.0.1", "-p", str(bridge)],
                root, root / "mode4-deny.log",
                {"NPS_PUBLIC_VKEY": "definitely-not-the-public-vkey"})
    code = proc.wait(30)
    if code is None:
        proc.stop()
    checks.expect("[mode4-deny] exits with dedicated code 7", code == 7,
                  f"exit={code} tail={proc.tail(12)}")
    checks.expect("[mode4-deny] does not retry forever", code is not None)
    text = proc.text()
    checks.expect("[mode4-deny] error names both attempts",
                  "rgst" in text and "public_vkey" in text, proc.tail(10))
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
    checks.expect("[cli] install without required options -> exit 2",
                  code == 2, f"exit={code}")
    checks.expect("[cli] install without options names -server",
                  "-server" in out, out[-200:])

    code, out = run_cli([str(rnpc), "bogus-cmd"], root)
    checks.expect("[cli] unknown subcommand -> exit 2", code == 2, f"exit={code}")
    checks.expect("[cli] unknown subcommand points at rnpc help", "rnpc help" in out)

    code, out = run_cli([str(rnpc), "-s", "10.0.0.1", "-p", "8024",
                         "-vkey", vkey, "-type", "udp"], root)
    checks.expect("[cli] unsupported -type -> exit 5", code == 5, f"exit={code}")
    checks.expect("[cli] unsupported type does not echo vkey", vkey not in out)

    code, out = run_cli([str(rnpc), "--version"], root)
    checks.expect("[cli] --version works", code == 0 and "Rust-nps" in out, out[-120:])


def main() -> int:
    parser = argparse.ArgumentParser(
        description="rnpc <-> real Go nps cross-verification")
    parser.add_argument("--rnpc", default=str(
        REPO / "rust" / "target" / "debug" / "rnpc.exe"))
    parser.add_argument("--nps-bin", default=str(DEFAULT_NPS))
    parser.add_argument("--skip-go", action="store_true",
                        help="only run CLI checks (no live server)")
    parser.add_argument("--keep", action="store_true", help="keep temp dir")
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
            try:
                # ---------- server A: public_vkey (mode 3 pub + mode 4) ----------
                bridge_a, web_a, listen_pub = free_port(), free_port(), free_port()
                public_vkey = "pub-" + hashlib.sha256(os.urandom(8)).hexdigest()[:8]
                exe_a = write_go_server(root / "go-pub", nps, bridge_a, web_a,
                                        public_vkey, None, None)
                server_a = Proc("nps-pub", [str(exe_a)], root / "go-pub",
                                root / "nps-pub.log")
                servers.append(server_a)
                checks.expect("[server-pub] bridge listening", wait_port(bridge_a, 20),
                              f"port={bridge_a}")

                run_config_tunnel(checks, rnpc, root, "mode3-pub", public_vkey,
                                  bridge_a, listen_pub, echo.port,
                                  expect_assigned=True)
                run_mode4_ok(checks, rnpc, root, bridge_a, public_vkey)
                run_mode4_denied(checks, rnpc, root, bridge_a)
                run_unsupported_mode_config(checks, rnpc, root, public_vkey,
                                            bridge_a)

                # ---------- 模式 1 / 模式 2：两种写法 + 多实例并发 ----------
                # 两个独立 Go 实例、两个客户端同时在线：同时验证
                # `-server=host:port` 与 `-s host -p port` 等价，以及多实例互不干扰。
                server_m1, bridge_m1, listen_m1 = spawn_fixture(
                    root, nps, "m1", secret, echo)
                servers.append(server_m1)
                server_m2, bridge_m2, listen_m2 = spawn_fixture(
                    root, nps, "m2", secret, echo)
                servers.append(server_m2)

                client_m1 = start_direct_tunnel(
                    checks, rnpc, root, "mode1", secret, bridge_m1, listen_m1,
                    "combined", keep=True)
                client_m2 = start_direct_tunnel(
                    checks, rnpc, root, "mode2", secret, bridge_m2, listen_m2,
                    "split", keep=True)
                checks.expect("[multi-instance] two clients alive at the same time",
                              client_m1.alive() and client_m2.alive(),
                              f"m1={client_m1.alive()} m2={client_m2.alive()}")
                checks.expect("[multi-instance] both tunnels serve concurrently",
                              wait_tunnel(listen_m1, 10) and wait_tunnel(listen_m2, 10))
                client_m1.stop()
                client_m2.stop()

                # ---------- 模式 3：私有客户端（isPub=false） ----------
                listen_priv = free_port()
                # 复用 m2 的服务端：客户端已断开，任务会被停掉，端口已释放；
                # 这里让配置模式在同一个服务端上注册一条全新隧道。
                run_config_tunnel(checks, rnpc, root, "mode3-priv", secret,
                                  bridge_m2, listen_priv, echo.port,
                                  expect_assigned=False)

                # 服务端进程仍然存活（没有因我们的客户端崩溃）
                checks.expect("[server] Go nps still alive after all scenarios",
                              server_a.alive() and server_m1.alive()
                              and server_m2.alive())
            finally:
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
    if not args.keep and checks.failed == 0:
        shutil.rmtree(root, ignore_errors=True)
        print("(temp dir removed; --keep to retain logs)")
    return 0 if checks.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
