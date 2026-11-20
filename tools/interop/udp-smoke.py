#!/usr/bin/env python3
"""Real Go npc <-> Rust-UDP-tunnel interop smoke test.

What this proves (nothing here mocks the protocol on the server side):
  * a REAL Go npc.exe (0.26.10 / core 0.26.0) started with `-config=npc.conf`
    containing a `[udp] mode=udp` section registers its task against the Rust
    UdpTunnel bridge (real conf handshake), then opens main+chan mux sessions;
  * the Rust `UdpTunnel` serves a real UDP listener, opens one mux sub-stream per
    source address with `ConnType="udp"`, and the real npc dials the target with
    `net.DialTimeout("udp", ...)` and copies bytes verbatim;
  * payload integrity: single datagram, 100 sequential datagrams, concurrent
    different source ports (addrMap isolation), and one large ~60 KiB payload
    (reassembled across mux fragments, which is inherent to the mux framing).

Two server modes:
  * (default) harness: the `udp_interop_harness` test binary from
    crates/nps-server/tests/udp_tunnel.rs starts the legacy Bridge + a conf
    handler that accepts the task registration + a real UdpTunnel bound to the
    UDP port given via env.
  * --server-bin <rnps.exe>: the REAL production server binary. Two sub-paths:
      - default: JSON `udp_tunnels` defines the tunnel, npc runs plain
        (-server/-vkey). Exercises Server::start wiring + config parsing.
      - --conf-register: JSON has no udp_tunnels; npc runs with
        `-config=npc.conf` whose `[udp] mode=udp` section is registered over the
        legacy `conf` handshake (conf.rs -> register_udp_task -> UdpTunnel).

Run:
    python -I udp-smoke.py --npc-bin <npc.exe> [--harness-bin <udp_tunnel.exe>]
    python -I udp-smoke.py --npc-bin <npc.exe> --repo D:/Developing/NPS/rust
    python -I udp-smoke.py --npc-bin <npc.exe> --server-bin <rnps.exe>

Exit codes:
    0  all checks passed
    1  at least one check failed (logs preserved, tails printed)
    2  usage / missing local files
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from pathlib import Path

# --------------------------------------------------------------------------
# tunables
# --------------------------------------------------------------------------
LARGE_PAYLOAD = 60000          # < 65507 (max IPv4 UDP payload)
SEQ_PACKETS = 100
CONCURRENT_SOURCES = 4
START_TIMEOUT = 30.0
ECHO_TIMEOUT = 8.0


class Fail(Exception):
    pass


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------
def free_tcp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def free_udp_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tail(path: Path, limit: int = 6000) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - limit))
            return f.read().decode("utf-8", "replace")
    except OSError as e:
        return f"<cannot read {path}: {e}>"


def log(msg: str) -> None:
    print(msg, flush=True)


class Checks:
    def __init__(self) -> None:
        self.results: list[tuple[bool, str, str]] = []

    def ok(self, name: str, detail: str = "") -> None:
        self.results.append((True, name, detail))
        log(f"[PASS] {name}" + (f"  ({detail})" if detail else ""))

    def fail(self, name: str, detail: str = "") -> None:
        self.results.append((False, name, detail))
        log(f"[FAIL] {name}" + (f"  ({detail})" if detail else ""))

    def require(self, cond: bool, name: str, detail: str = "") -> None:
        (self.ok if cond else self.fail)(name, detail)


class UdpEchoServer:
    """Echo datagrams back to their exact sender (per-datagram echo)."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.3)
        self.addr = self.sock.getsockname()
        self.seen: dict[bytes, int] = {}
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def start(self) -> "UdpEchoServer":
        self.thread.start()
        return self

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            with self.lock:
                self.seen[data] = self.seen.get(data, 0) + 1
            try:
                self.sock.sendto(data, addr)
            except OSError:
                pass

    def seen_count(self, data: bytes) -> int:
        with self.lock:
            return self.seen.get(data, 0)

    def stop(self) -> None:
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass


def spawn(name: str, argv: list[str], env: dict, log_path: Path, cwd: Path) -> dict:
    shown = " ".join("<redacted-vkey>" if a.startswith("-vkey=") else a for a in argv)
    log(f"[run] {name}: {shown}")
    fh = open(log_path, "wb")
    proc = subprocess.Popen(
        argv,
        stdout=fh,
        stderr=subprocess.STDOUT,
        cwd=str(cwd),
        env=env,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return {"proc": proc, "fh": fh, "log": log_path, "name": name}


def stop_proc(handle: dict | None, timeout: float = 6.0) -> None:
    if not handle:
        return
    proc: subprocess.Popen = handle["proc"]
    try:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=timeout)
    finally:
        try:
            handle["fh"].close()
        except OSError:
            pass


def ensure_alive(handle: dict) -> None:
    proc = handle["proc"]
    if proc.poll() is not None:
        raise Fail(
            f"{handle['name']} exited early with code {proc.returncode}:\n"
            f"{tail(handle['log'])}"
        )


def solve_harness_bin(repo: Path, explicit: str | None) -> Path:
    if explicit:
        p = Path(explicit)
        if not p.is_file():
            raise Fail(f"harness binary not found: {p}")
        return p
    log("[run] locating udp_tunnel test binary via cargo test --no-run ...")
    cmd = [
        "cargo", "test", "-p", "nps-server", "--test", "udp_tunnel",
        "--no-run", "--message-format=json",
    ]
    out = subprocess.run(cmd, cwd=str(repo), capture_output=True, text=True)
    if out.returncode != 0:
        raise Fail(f"cargo test --no-run failed:\n{out.stderr[-4000:]}")
    found = None
    for line in out.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if msg.get("reason") != "compiler-artifact":
            continue
        target = msg.get("target") or {}
        if target.get("name") == "udp_tunnel" and msg.get("executable"):
            found = Path(msg["executable"])
    if not found or not found.is_file():
        raise Fail("cargo did not report a udp_tunnel test executable")
    return found


def start_rnps(server_bin: Path, run_dir: Path, bridge_port: int, tunnel_port: int,
               target_addr: tuple[str, int], vkey: str, conf_register: bool = False) -> dict:
    """Start the real rnps binary.

    `conf_register=False`: the JSON `udp_tunnels` list defines the tunnel.
    `conf_register=True` : JSON has no udp_tunnels; the tunnel must come from
    npc's `[udp] mode=udp` conf registration (conf.rs path).
    """
    cfg = {
        "bridge_addr": f"127.0.0.1:{bridge_port}",
        "web_addr": f"127.0.0.1:{free_tcp_port()}",
        "clients": [{"id": 1, "name": "udp-interop", "vkey": vkey}],
        "tunnels": [],
        "conf_register": conf_register,
        "conf_listen_host": "127.0.0.1",
    }
    if not conf_register:
        cfg["udp_tunnels"] = [
            {
                "id": 1,
                "name": "udp-echo",
                "client_id": 1,
                "listen_addr": f"127.0.0.1:{tunnel_port}",
                "target_addr": f"{target_addr[0]}:{target_addr[1]}",
                "enabled": True,
            }
        ]
    cfg_path = run_dir / "config.json"
    cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    env = dict(os.environ)
    env.setdefault("NPS_ADMIN_TOKEN", secrets.token_urlsafe(24))
    return spawn("rnps", [str(server_bin), "--config", str(cfg_path)], env,
                 run_dir / "rnps.log", run_dir)


def wait_ready(path: Path, handle: dict, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        ensure_alive(handle)
        if path.is_file():
            return
        time.sleep(0.1)
    raise Fail(f"harness did not become ready within {timeout}s:\n{tail(handle['log'])}")


def udp_probe(addr: tuple[str, int], tcp_udp_port: int, timeout: float) -> tuple[bool, str]:
    """Send one probe datagram and wait for its echo (retried by caller)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.6)
    payload = b"nps-udp-probe-" + secrets.token_hex(8).encode()
    try:
        sock.sendto(payload, addr)
        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            return False, "timeout"
        except ConnectionResetError:
            # Windows surfaces the ICMP port-unreachable from a *previous*
            # probe as WSAECONNRESET on the next recvfrom. Treat as "not up yet".
            return False, "port-unreachable (ICMP)"
        if data != payload:
            return False, f"echo mismatch (got {data[:32]!r} len={len(data)})"
        return True, "ok"
    finally:
        sock.close()


def recv_exact_total(sock: socket.socket, total: int, timeout: float) -> tuple[bytes, list[int]]:
    """Collect datagrams until `total` bytes arrived; returns (bytes, chunk_sizes)."""
    deadline = time.monotonic() + timeout
    buf = bytearray()
    chunks: list[int] = []
    while len(buf) < total:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sock.settimeout(min(remaining, 2.0))
        try:
            data, _ = sock.recvfrom(65535)
        except socket.timeout:
            break
        except ConnectionResetError:
            # ICMP port-unreachable noise on Windows; keep waiting.
            continue
        buf += data
        chunks.append(len(data))
    return bytes(buf), chunks


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------
def run(args: argparse.Namespace) -> int:
    npc_bin = Path(args.npc_bin)
    if not npc_bin.is_file():
        raise Fail(f"npc binary not found: {npc_bin}")
    repo = Path(args.repo).resolve()
    use_rnps = args.server_bin is not None
    server_bin = Path(args.server_bin) if use_rnps else None
    if use_rnps and not server_bin.is_file():
        raise Fail(f"server binary not found: {server_bin}")
    harness_bin = None if use_rnps else solve_harness_bin(repo, args.harness_bin)

    run_dir = Path(tempfile.mkdtemp(prefix="nps-udp-smoke-"))
    checks = Checks()
    echo = None
    harness = None
    npc = None

    try:
        echo = UdpEchoServer().start()
        echo_addr = echo.addr
        bridge_port = free_tcp_port()
        tunnel_port = free_udp_port()
        vkey = secrets.token_urlsafe(24)
        ready_file = run_dir / "harness.ready"

        if use_rnps:
            harness = start_rnps(server_bin, run_dir, bridge_port, tunnel_port, echo_addr, vkey,
                                 conf_register=args.conf_register)
            # rnps has no ready file: poll its ports until it answers
            deadline = time.monotonic() + START_TIMEOUT
            ready = False
            while time.monotonic() < deadline:
                ensure_alive(harness)
                probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                probe.settimeout(0.4)
                try:
                    probe.connect(("127.0.0.1", bridge_port))
                    ready = True
                except OSError:
                    ready = False
                finally:
                    probe.close()
                if ready:
                    break
                time.sleep(0.15)
            if not ready:
                raise Fail("rnps did not start listening:" + tail(harness["log"]))
            checks.ok("real rnps server ready", f"bridge={bridge_port} udp={tunnel_port} target={echo_addr}")
        else:
            env = dict(os.environ)
            env.update({
                "NPS_UDP_HARNESS_BRIDGE": f"127.0.0.1:{bridge_port}",
                "NPS_UDP_HARNESS_TUNNEL": f"127.0.0.1:{tunnel_port}",
                "NPS_UDP_HARNESS_TARGET": f"{echo_addr[0]}:{echo_addr[1]}",
                "NPS_UDP_HARNESS_VKEY": vkey,
                "NPS_UDP_HARNESS_READY": str(ready_file),
            })
            harness = spawn(
                "harness",
                [str(harness_bin), "--exact", "udp_interop_harness", "--ignored", "--nocapture"],
                env, run_dir / "harness.log", repo,
            )
            wait_ready(ready_file, harness, START_TIMEOUT)
            checks.ok("harness ready", f"bridge={bridge_port} udp={tunnel_port} target={echo_addr}")

        if use_rnps and not args.conf_register:
            # Production path A: the server owns the UDP tunnel from its JSON
            # `udp_tunnels` config, so npc only needs bridge+vkey (plain mode).
            npc = spawn(
                "npc",
                [str(npc_bin), f"-server=127.0.0.1:{bridge_port}", f"-vkey={vkey}",
                 "-type=tcp", "-log=stdout", "-log_level=7"],
                dict(os.environ), run_dir / "npc.log", run_dir,
            )
            log("[npc] plain mode (-server/-vkey); UDP tunnel comes from rnps JSON config")
        else:
            # ---- real Go npc with a `mode=udp` config file --------------------
            # (production --conf-register: conf.rs creates the UDP listener;
            #  default harness mode: the harness conf handler accepts the task)
            conf = run_dir / "npc.conf"
            conf.write_text(
                "[common]\n"
                f"server_addr=127.0.0.1:{bridge_port}\n"
                f"vkey={vkey}\n"
                "conn_type=tcp\n"
                "auto_reconnection=true\n"
                "\n"
                "[udp-echo]\n"
                "mode=udp\n"
                f"server_port={tunnel_port}\n"
                f"target_addr={echo_addr[0]}:{echo_addr[1]}\n",
                encoding="utf-8",
            )
            log(f"[npc.conf]\n{conf.read_text(encoding='utf-8')}")

            npc = spawn(
                "npc",
                [str(npc_bin), f"-config={conf}", "-log=stdout", "-log_level=7"],
                dict(os.environ), run_dir / "npc.log", run_dir,
            )

        # ---- wait until the tunnel actually forwards ----------------------
        tunnel_addr = ("127.0.0.1", tunnel_port)
        deadline = time.monotonic() + START_TIMEOUT * 2
        last = "not started"
        while time.monotonic() < deadline:
            ensure_alive(harness)
            ensure_alive(npc)
            ok, last = udp_probe(tunnel_addr, tunnel_port, 1.5)
            if ok:
                break
            time.sleep(0.3)
        checks.require(ok, "real npc connects and first UDP roundtrip echoes", last)
        if not ok:
            raise Fail("tunnel never forwarded a UDP datagram")

        # ---- 1. single datagram byte-exact --------------------------------
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(ECHO_TIMEOUT)
        payload = b"single-" + secrets.token_bytes(970)
        sock.sendto(payload, tunnel_addr)
        got, _ = sock.recvfrom(65535)
        checks.require(
            got == payload,
            "single datagram roundtrip is byte-exact",
            f"len={len(payload)} sha256={sha256(payload)[:16]}…",
        )

        # ---- 2. 100 sequential datagrams ----------------------------------
        seq_ok = 0
        seq_fail: list[str] = []
        t0 = time.monotonic()
        for i in range(SEQ_PACKETS):
            body = f"seq-{i:03d}-".encode() + secrets.token_bytes(random.randint(4, 900))
            sock.sendto(body, tunnel_addr)
            try:
                got, _ = sock.recvfrom(65535)
            except socket.timeout:
                seq_fail.append(f"#{i}: timeout")
                continue
            except ConnectionResetError:
                seq_fail.append(f"#{i}: icmp-reset")
                continue
            if got == body:
                seq_ok += 1
            else:
                seq_fail.append(f"#{i}: len {len(got)} != {len(body)}")
        elapsed = time.monotonic() - t0
        checks.require(
            seq_ok == SEQ_PACKETS,
            f"{SEQ_PACKETS} sequential datagrams byte-exact",
            f"{seq_ok}/{SEQ_PACKETS} in {elapsed:.2f}s" + ("" if not seq_fail else f"; {seq_fail[:3]}"),
        )
        sock.close()

        # ---- 3. concurrent different source ports (addrMap isolation) -----
        results: list[tuple[int, bool, str]] = []
        lock = threading.Lock()

        def worker(idx: int) -> None:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(ECHO_TIMEOUT)
            mine = f"src-{idx}-".encode() + secrets.token_bytes(700 + idx * 37)
            try:
                for _ in range(3):  # a few datagrams per source
                    s.sendto(mine, tunnel_addr)
                    got, _ = s.recvfrom(65535)
                    if got != mine:
                        raise Fail(f"source {idx} got foreign/incorrect payload")
                with lock:
                    results.append((idx, True, f"port={s.getsockname()[1]}"))
            except Exception as e:  # noqa: BLE001 - collected and reported
                with lock:
                    results.append((idx, False, str(e)))
            finally:
                s.close()

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(CONCURRENT_SOURCES)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=ECHO_TIMEOUT + 5)
        ok_sources = sum(1 for _, ok, _ in results if ok)
        checks.require(
            ok_sources == CONCURRENT_SOURCES,
            f"{CONCURRENT_SOURCES} concurrent source ports isolated",
            f"{ok_sources}/{CONCURRENT_SOURCES}; ports="
            + ",".join(d for idx, _, d in sorted(results) if d.startswith("port=")),
        )

        # ---- 4. large payload (~60 KiB, reassembled across mux fragments) --
        big_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        big = bytes(random.getrandbits(8) for _ in range(2048))
        big = (big * ((LARGE_PAYLOAD // len(big)) + 1))[:LARGE_PAYLOAD]
        big_sock.sendto(big, tunnel_addr)
        reassembled, chunks = recv_exact_total(big_sock, len(big), ECHO_TIMEOUT * 2)
        big_sock.close()
        checks.require(
            reassembled == big,
            f"large {LARGE_PAYLOAD}-byte payload byte-exact after reassembly",
            f"sent sha256={sha256(big)[:16]}… recv sha256={sha256(reassembled)[:16]}… "
            f"datagrams={len(chunks)} sizes={chunks[:6]}{'…' if len(chunks) > 6 else ''}",
        )
        # also confirm the echo target actually saw the original datagram
        checks.require(
            echo.seen_count(big) >= 1 or len(chunks) > 1,
            "echo target observed the large payload (datagram split is expected)",
            f"exact-datagram hits={echo.seen_count(big)}, fragments={len(chunks)}",
        )

        # ---- summary -------------------------------------------------------
        log("")
        ok = sum(1 for passed, _, _ in checks.results if passed)
        total = len(checks.results)
        log(f"udp-smoke: {ok}/{total} checks passed")
        for passed, name, detail in checks.results:
            if not passed:
                log(f"  FAILED: {name} ({detail})")
        return 0 if ok == total else 1

    except Fail as e:
        log(f"[FAIL] {e}")
        return 1
    except Exception:  # noqa: BLE001 - report and fail the run
        traceback.print_exc()
        return 1
    finally:
        stop_proc(npc)
        stop_proc(harness)
        if echo is not None:
            echo.stop()
        if npc is not None:
            log("--- npc.log tail ---")
            log(tail(npc["log"]))
        if harness is not None:
            log(f"--- {harness['name']}.log tail ---")
            log(tail(harness["log"]))
        log(f"[run dir] {run_dir}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Real Go npc <-> Rust UDP tunnel smoke test")
    ap.add_argument("--npc-bin", required=True, help="path to the real Go npc.exe")
    ap.add_argument("--harness-bin", default=None,
                    help="udp_tunnel test binary (auto-located via cargo when omitted)")
    ap.add_argument("--server-bin", default=None,
                    help="use the real rnps.exe (JSON udp_tunnels config) instead of the harness")
    ap.add_argument("--conf-register", action="store_true",
                    help="with --server-bin: register the tunnel through npc.conf's "
                         "[udp] mode=udp conf handshake instead of JSON udp_tunnels")
    ap.add_argument("--repo", default=str(Path(__file__).resolve().parents[2] / "rust"),
                    help="rust workspace root (default: ../../rust)")
    args = ap.parse_args()
    try:
        return run(args)
    except Fail as e:
        log(f"[FAIL] {e}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
