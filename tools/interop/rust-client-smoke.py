#!/usr/bin/env python3
"""Black-box interop smoke test for the Rust npc client (`rnpc`).

Two directions are exercised against the same real echo service:

  A. real Go `nps` server (built read-only from resources/nps)  <->  Rust `rnpc`
  B. Rust `rnps` server (rust/target/debug/rnps.exe)            <->  Rust `rnpc`

Checks per direction:
  * wrong vkey is rejected (exit code 4) and the vkey never appears in logs
  * correct vkey comes online and a TCP tunnel works
  * a >=1 MiB payload is echoed byte-for-byte (sha256 compared)
  * 4 concurrent tunnel streams are byte-exact
  * stopping the target service closes streams without killing the client;
    restarting it restores service
  * client restart reconnects and restores the tunnel
  * Ctrl+C (SIGINT / CTRL_BREAK_EVENT) exits 0

Usage (run isolated, no third-party imports):
    python -I tools/interop/rust-client-smoke.py

Optional:
    --nps-bin PATH       real Go nps.exe (default tools/interop/server/nps.exe)
    --npsc-bin PATH      Rust client (default rust/target/debug/rnpc.exe)
    --npsd-bin PATH      Rust server (default rust/target/debug/rnps.exe)
    --skip-go            skip direction A
    --skip-rust-server   skip direction B
    --keep               keep temp dirs / logs

Exit codes: 0 all passed, 1 a check failed, 2 a required binary is missing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
DEFAULT_NPS_BIN = REPO / "tools" / "interop" / "server" / "nps.exe"
DEFAULT_NPSC_BIN = REPO / "rust" / "target" / "debug" / "rnpc.exe"
DEFAULT_NPSD_BIN = REPO / "rust" / "target" / "debug" / "rnps.exe"
LOG_ROOT = REPO / "tools" / "interop" / "logs"

CHUNK = 32 * 1024


class SmokeFail(Exception):
    pass


class Checks:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0
        self.failures: list[str] = []

    def ok(self, name: str, detail: str = "") -> None:
        self.passed += 1
        suffix = f" [{detail}]" if detail else ""
        print(f"[ok]   {name}{suffix}", flush=True)

    def fail(self, name: str, detail: str = "") -> None:
        self.failed += 1
        text = f"{name}: {detail}" if detail else name
        self.failures.append(text)
        print(f"[FAIL] {name}" + (f" [{detail}]" if detail else ""), flush=True)

    def expect(self, name: str, condition: bool, detail: str = "") -> bool:
        if condition:
            self.ok(name, detail)
        else:
            self.fail(name, detail)
        return condition


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


def _template(seed: int) -> bytes:
    base = bytearray()
    state = seed & 0xFFFFFFFF
    for _ in range(256):
        state = (1103515245 * state + 12345) & 0x7FFFFFFF
        base.append(state & 0xFF)
    return bytes(base)


def _chunk(template: bytes, index: int, length: int) -> bytes:
    start = (index * 131) % len(template)
    data = template[start:] + template[:start]
    reps = (length + len(data) - 1) // len(data)
    return (data * reps)[:length]


def recv_exact(sock: socket.socket, length: int, label: str) -> bytes:
    buf = bytearray()
    while len(buf) < length:
        chunk = sock.recv(min(CHUNK, length - len(buf)))
        if not chunk:
            raise SmokeFail(
                f"{label}: EOF after {len(buf)}/{length} bytes "
                f"(server closed the tunnel)")
        buf.extend(chunk)
    return bytes(buf)


class EchoService:
    """Threaded byte-exact echo server on 127.0.0.1."""

    def __init__(self, port: int = 0) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen(64)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()
        self._conns: list[socket.socket] = []
        self._lock = threading.Lock()

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with self._lock:
                self._conns.append(conn)
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            while True:
                data = conn.recv(CHUNK)
                if not data:
                    break
                conn.sendall(data)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass
        with self._lock:
            for conn in self._conns:
                try:
                    conn.close()
                except OSError:
                    pass
            self._conns.clear()


def echo_once(port: int, total: int, seed: int, timeout: float = 30.0) -> str:
    """Send `total` deterministic bytes, read the exact echo, return sha256."""
    template = _template(seed)
    tx = hashlib.sha256()
    rx = hashlib.sha256()
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        errors: list[BaseException] = []

        def writer() -> None:
            try:
                offset = index = 0
                while offset < total:
                    n = min(CHUNK, total - offset)
                    data = _chunk(template, index, n)
                    sock.sendall(data)
                    tx.update(data)
                    offset += n
                    index += 1
            except BaseException as exc:  # noqa: BLE001 - surfaced below
                errors.append(exc)

        thread = threading.Thread(target=writer, daemon=True)
        thread.start()

        offset = index = 0
        while offset < total:
            n = min(CHUNK, total - offset)
            expect = _chunk(template, index, n)
            got = recv_exact(sock, n, f"echo seed={seed} size={total}")
            if got != expect:
                diff = next(i for i in range(n) if got[i] != expect[i])
                raise SmokeFail(
                    f"echo mismatch at stream offset {offset + diff} "
                    f"(seed={seed}, size={total})")
            rx.update(got)
            offset += n
            index += 1

        thread.join(timeout=timeout)
        if thread.is_alive():
            raise SmokeFail(f"writer thread stuck (seed={seed})")
        if errors:
            raise SmokeFail(f"writer error: {errors[0]!r}")
    return rx.hexdigest()


def wait_tunnel(port: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            echo_once(port, 4096, seed=7, timeout=2.0)
            return True
        except (OSError, SmokeFail):
            time.sleep(0.1)
    return False


class Proc:
    def __init__(self, label: str, args: list[str], cwd: Path, log_path: Path,
                 env: dict[str, str] | None = None) -> None:
        self.label = label
        self.args = list(args)
        self.cwd = Path(cwd)
        self.log_path = Path(log_path)
        self.extra_env = dict(env or {})
        self.log_file = open(self.log_path, "w", encoding="utf-8", errors="replace")
        full_env = os.environ.copy()
        full_env.update(self.extra_env)
        self.popen = subprocess.Popen(
            self.args,
            cwd=str(self.cwd),
            stdin=subprocess.DEVNULL,
            stdout=self.log_file,
            stderr=subprocess.STDOUT,
            env=full_env,
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )

    def restart(self, log_name: str) -> "Proc":
        self.stop()
        return Proc(self.label, self.args, self.cwd,
                    self.log_path.with_name(f"{log_name}.log"), self.extra_env)

    def alive(self) -> bool:
        return self.popen.poll() is None

    def log_text(self) -> str:
        try:
            self.log_file.flush()
        except (OSError, ValueError):
            pass
        try:
            return self.log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    def log_tail(self, lines: int = 30) -> str:
        return "\n".join(self.log_text().splitlines()[-lines:])

    def interrupt(self) -> None:
        if not self.alive():
            return
        if os.name == "nt":
            self.popen.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            self.popen.send_signal(signal.SIGINT)

    def stop(self, timeout: float = 5.0) -> None:
        if self.alive():
            self.popen.terminate()
            try:
                self.popen.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.popen.kill()
                self.popen.wait(timeout=timeout)
        self.close()

    def wait(self, timeout: float) -> int | None:
        try:
            return self.popen.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def close(self) -> None:
        try:
            self.log_file.close()
        except (OSError, ValueError):
            pass


def start_client(label: str, npsc: Path, server_port: int, vkey: str,
                 cwd: Path, log_dir: Path) -> Proc:
    return Proc(
        label,
        [str(npsc),
         f"-server=127.0.0.1:{server_port}",
         f"-vkey={vkey}",
         "-type=tcp",
         "-log_level=debug"],
        cwd=cwd,
        log_path=log_dir / f"{label}.log",
    )


def assert_log_redacted(checks: Checks, proc: Proc, vkey: str, label: str) -> None:
    text = proc.log_text()
    digest = hashlib.md5(vkey.encode()).hexdigest()
    checks.expect(f"{label}: vkey not present in client log", vkey not in text)
    checks.expect(f"{label}: md5(vkey) not present in client log", digest not in text)


def run_cli(checks: Checks, args: list[str], cwd: Path, work_dir: Path,
            label: str, expected_exit: int, forbidden: str | None = None) -> None:
    result = subprocess.run(
        args, cwd=str(cwd), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=30, text=True, encoding="utf-8", errors="replace")
    output = result.stdout or ""
    checks.expect(f"{label} exits with code {expected_exit}",
                  result.returncode == expected_exit,
                  f"exit={result.returncode} output={output[-300:]!r}")
    if forbidden is not None:
        checks.expect(f"{label} does not echo the vkey", forbidden not in output)


def check_cli_and_unreachable(npsc: Path, checks: Checks, log_dir: Path,
                              work_dir: Path) -> None:
    secret = "cli-secret-" + hashlib.sha256(os.urandom(16)).hexdigest()[:12]
    run_cli(checks,
            [str(npsc), "-server=127.0.0.1:1", f"-vkey={secret}", "-type=udp"],
            work_dir, work_dir, "[cli] unsupported -type=udp", 5)
    run_cli(checks,
            [str(npsc), "-vkey=" + secret, "-type=tcp"],
            work_dir, work_dir, "[cli] missing -server", 2)
    run_cli(checks,
            [str(npsc), "-server=not-an-address", "-vkey=" + secret],
            work_dir, work_dir, "[cli] invalid server address", 2)

    # Closed loopback port: must fail fast with the dedicated unreachable code.
    closed = free_port()
    proc = start_client("npsc-unreachable", npsc, closed, secret, work_dir, log_dir)
    rc = proc.wait(20)
    if rc is None:
        proc.stop()
    checks.expect("[cli] unreachable server exits with code 3", rc == 3,
                  f"exit={rc} tail={proc.log_tail(8)!r}")
    checks.expect("[cli] unreachable log does not echo vkey", secret not in proc.log_text())
    proc.close()


def write_go_server_config(run_dir: Path, bridge: int, web: int, listen: int,
                           target: int, vkey: str, nps_bin: Path) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    conf = run_dir / "conf"
    conf.mkdir(exist_ok=True)
    shutil.copy2(nps_bin, run_dir / "nps.exe")

    (conf / "nps.conf").write_text(
        "\n".join([
            "appname = nps",
            "runmode = dev",
            "bridge_type = tcp",
            f"bridge_port = {bridge}",
            "bridge_ip = 127.0.0.1",
            "public_vkey =",
            "log_level = 6",
            f"web_host = 127.0.0.1",
            "web_username = admin",
            "web_password = " + hashlib.md5(vkey.encode()).hexdigest(),
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
        ]),
        encoding="utf-8",
    )

    client = {
        "Cnf": {"U": "", "P": "", "Compress": False, "Crypt": False},
        "Id": 1,
        "VerifyKey": vkey,
        "Addr": "",
        "Remark": "rust-client-smoke",
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
        "ConfigConnAllow": False,
        "MaxTunnelNum": 0,
        "Version": "",
    }
    tunnel = {
        "Id": 1,
        "Port": listen,
        "ServerIp": "127.0.0.1",
        "Mode": "tcp",
        "Status": True,
        "RunStatus": True,
        "Client": client,
        "Ports": "",
        "Flow": {"ExportFlow": 0, "InletFlow": 0, "FlowLimit": 0},
        "Password": "",
        "Remark": "echo",
        "TargetAddr": f"127.0.0.1:{target}",
        "NoStore": False,
        "LocalPath": "",
        "StripPre": "",
        "Target": {"TargetStr": f"127.0.0.1:{target}", "TargetArr": None,
                   "LocalProxy": False},
        "MultiAccount": None,
    }
    (conf / "clients.json").write_text(
        json.dumps(client, separators=(",", ":")) + "\n*#*", encoding="utf-8")
    (conf / "tasks.json").write_text(
        json.dumps(tunnel, separators=(",", ":")) + "\n*#*", encoding="utf-8")
    (conf / "hosts.json").write_text("", encoding="utf-8")
    return run_dir / "nps.exe"


def write_rust_server_config(run_dir: Path, bridge: int, web: int, listen: int,
                             target: int, vkey: str) -> Path:
    run_dir.mkdir(parents=True, exist_ok=True)
    config = {
        "bridge_addr": f"127.0.0.1:{bridge}",
        "web_addr": f"127.0.0.1:{web}",
        "clients": [{"id": 1, "name": "rust-client-smoke", "vkey": vkey}],
        "tunnels": [{
            "id": 1,
            "name": "echo",
            "client_id": 1,
            "listen_addr": f"127.0.0.1:{listen}",
            "target_addr": f"127.0.0.1:{target}",
            "enabled": True,
        }],
    }
    path = run_dir / "nps.json"
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return path


def run_direction(name: str, server_proc: Proc, server_port: int, listen_port: int,
                  echo: EchoService, npsc: Path, checks: Checks, log_dir: Path,
                  work_dir: Path, vkey: str, servers: list[Proc]) -> None:
    """Shared assertions for one server implementation."""
    prefix = f"[{name}]"

    checks.expect(f"{prefix} server listens on bridge port", wait_port(server_port, 15),
                  f"port={server_port}")

    # ---- wrong vkey is rejected, exit code 4, no secret in logs ----
    bad = start_client(f"npsc-bad-{name}", npsc, server_port,
                       "wrong-" + vkey, work_dir, log_dir)
    rc = bad.wait(12)
    if rc is None:
        bad.stop()
    checks.expect(f"{prefix} wrong vkey exits with code 4", rc == 4,
                  f"exit={rc} tail={bad.log_tail(8)!r}")
    bad_text = bad.log_text()
    checks.expect(f"{prefix} wrong vkey not echoed in logs",
                  ("wrong-" + vkey) not in bad_text)
    bad.close()

    # ---- correct vkey: tunnel comes up ----
    client = start_client(f"npsc-{name}", npsc, server_port, vkey,
                          work_dir, log_dir)
    try:
        up = wait_tunnel(listen_port, 25)
        checks.expect(f"{prefix} tunnel reachable after client connect", up,
                      f"listen={listen_port} tail={client.log_tail(12)!r}")
        if not up:
            return

        # ---- 1 MiB byte-exact ----
        digest = echo_once(listen_port, 1024 * 1024, seed=11, timeout=60)
        checks.ok(f"{prefix} 1 MiB echo byte-exact", f"sha256={digest[:16]}...")

        # ---- 4 concurrent streams ----
        sizes = [300 * 1024, 512 * 1024, 700 * 1024, 1024 * 1024]
        barrier = threading.Barrier(len(sizes))
        results: list[tuple[bool, str]] = [None] * len(sizes)  # type: ignore[list-item]

        def worker(index: int) -> None:
            try:
                barrier.wait(timeout=30)
                results[index] = (True, echo_once(
                    listen_port, sizes[index], seed=100 + index, timeout=90))
            except BaseException as exc:  # noqa: BLE001
                results[index] = (False, f"{type(exc).__name__}: {exc}")

        threads = [threading.Thread(target=worker, args=(i,), daemon=True)
                   for i in range(len(sizes))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=120)
        ok = all(result is not None and result[0] for result in results)
        checks.expect(f"{prefix} 4 concurrent streams byte-exact", ok,
                      "" if ok else repr(results))

        assert_log_redacted(checks, client, vkey, prefix)

        # ---- server restart: client must reconnect with backoff ----
        restarted_server = server_proc.restart(f"{name}-server-restart")
        servers.append(restarted_server)
        checks.expect(f"{prefix} restarted server listens", wait_port(server_port, 20),
                      f"port={server_port}")
        reconnected = wait_tunnel(listen_port, 45)
        checks.expect(f"{prefix} client reconnects after server restart", reconnected,
                      client.log_tail(15))

        # ---- target down: client survives; target back: service restored ----
        echo.close()
        time.sleep(0.3)
        checks.expect(f"{prefix} client stays alive after target stops", client.alive())

        dead_ok = False
        try:
            echo_once(listen_port, 4096, seed=3, timeout=5)
        except (OSError, SmokeFail):
            dead_ok = True
        checks.expect(f"{prefix} new stream fails while target is down", dead_ok)

        echo2 = EchoService(port=echo.port)
        try:
            restored = wait_tunnel(listen_port, 25)
            checks.expect(f"{prefix} tunnel recovers after target restarts", restored)

            # ---- client restart: reconnect + restore ----
            client.stop()
            checks.expect(f"{prefix} client stopped", not client.alive())
            time.sleep(0.3)
            client2 = start_client(f"npsc-{name}-restart", npsc, server_port, vkey,
                                   work_dir, log_dir)
            try:
                restarted = wait_tunnel(listen_port, 30)
                checks.expect(f"{prefix} tunnel restored after client restart", restarted,
                              client2.log_tail(12))
                if restarted:
                    echo_once(listen_port, 128 * 1024, seed=5, timeout=30)
                    checks.ok(f"{prefix} 128 KiB echo after restart byte-exact")
            finally:
                # ---- graceful Ctrl+C, exit code 0 ----
                client2.interrupt()
                rc = client2.wait(10)
                checks.expect(f"{prefix} Ctrl+C exits with code 0", rc == 0,
                              f"exit={rc} tail={client2.log_tail(8)!r}")
                if rc is None:
                    client2.stop()
                else:
                    client2.close()
        finally:
            echo2.close()
    finally:
        client.stop()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Interop smoke test for the Rust npsc client")
    parser.add_argument("--nps-bin", default=str(DEFAULT_NPS_BIN))
    parser.add_argument("--npsc-bin", default=str(DEFAULT_NPSC_BIN))
    parser.add_argument("--npsd-bin", default=str(DEFAULT_NPSD_BIN))
    parser.add_argument("--skip-go", action="store_true")
    parser.add_argument("--skip-rust-server", action="store_true")
    parser.add_argument("--keep", action="store_true")
    args = parser.parse_args()

    nps = Path(args.nps_bin)
    npsc = Path(args.npsc_bin)
    npsd = Path(args.npsd_bin)

    missing = []
    if not npsc.exists():
        missing.append(f"npsc missing: {npsc}")
    if not args.skip_go and not nps.exists():
        missing.append(f"Go nps missing: {nps}")
    if not args.skip_rust_server and not npsd.exists():
        missing.append(f"Rust npsd missing: {npsd}")
    if missing:
        for item in missing:
            print(f"[FAIL] {item}", file=sys.stderr)
        print("build first: cargo build -p nps-client -p nps-app", file=sys.stderr)
        return 2

    stamp = time.strftime("%Y%m%d-%H%M%S")
    log_dir = LOG_ROOT / f"rust-client-smoke-{stamp}"
    log_dir.mkdir(parents=True, exist_ok=True)
    print(f"== Rust npc interop smoke ({stamp}) ==", flush=True)
    print(f"logs: {log_dir}", flush=True)

    checks = Checks()
    echo = EchoService()
    print(f"echo target: 127.0.0.1:{echo.port}", flush=True)
    work_dir = log_dir / "work"
    work_dir.mkdir(parents=True, exist_ok=True)
    servers: list[Proc] = []

    try:
        check_cli_and_unreachable(npsc, checks, log_dir, work_dir)

        if not args.skip_go:
            bridge, web, listen = free_port(), free_port(), free_port()
            go_dir = log_dir / "go-server"
            go_vkey = "go-vkey-" + stamp + "-" + hashlib.sha256(os.urandom(16)).hexdigest()[:8]
            exe = write_go_server_config(go_dir, bridge, web, listen, echo.port,
                                         go_vkey, nps)
            server = Proc("nps-go", [str(exe)], cwd=go_dir,
                          log_path=log_dir / "nps-go.log")
            servers.append(server)
            run_direction("go-nps", server, bridge, listen, echo, npsc, checks,
                          log_dir, work_dir, go_vkey, servers)
        else:
            print("[skip] Go nps direction", flush=True)

        # A fresh echo target for the Rust server direction (the helper above
        # owns/close its own service).
        echo.close()
        echo = EchoService()

        if not args.skip_rust_server:
            bridge, web, listen = free_port(), free_port(), free_port()
            rust_dir = log_dir / "rust-server"
            rust_vkey = "rust-vkey-" + stamp + "-" + hashlib.sha256(os.urandom(16)).hexdigest()[:8]
            config = write_rust_server_config(rust_dir, bridge, web, listen,
                                              echo.port, rust_vkey)
            token = hashlib.sha256(os.urandom(32)).hexdigest()
            server = Proc("rnps", [str(npsd), "--config", str(config)], cwd=rust_dir,
                          log_path=log_dir / "rnps.log",
                          env={"NPS_ADMIN_TOKEN": token})
            servers.append(server)
            run_direction("rust-npsd", server, bridge, listen, echo, npsc, checks,
                          log_dir, work_dir, rust_vkey, servers)
        else:
            print("[skip] Rust npsd direction", flush=True)
    finally:
        echo.close()
        for server in servers:
            server.stop()
        if not args.keep:
            pass  # Logs are intentionally kept; temp work dirs live under logs.

    print(f"\n== summary: {checks.passed} passed, {checks.failed} failed ==",
          flush=True)
    if checks.failed:
        for failure in checks.failures:
            print(f"  - {failure}", flush=True)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())