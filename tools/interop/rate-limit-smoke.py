#!/usr/bin/env python3
"""验证限速在生产数据路径上真的生效（不是只存在于单元测试里）。

做法：真实 rnps + 真实 Go npc，配 rate_limit=100（KB/s），
通过隧道传输 1 MiB，测量实际耗时。不限速时应远小于 9 秒。
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

PASS: list[str] = []
FAIL: list[str] = []


def ok(m: str) -> None:
    PASS.append(m)
    print(f"  PASS  {m}", flush=True)


def bad(m: str) -> None:
    FAIL.append(m)
    print(f"  FAIL  {m}", flush=True)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Echo:
    def __init__(self) -> None:
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(120)
            while True:
                data = conn.recv(65536)
                if not data:
                    return
                conn.sendall(data)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


def run_case(server_bin: str, npc_bin: str, rate_kb: int, payload: int) -> float:
    """返回传输 payload 字节的耗时（秒）。"""
    run_dir = Path(tempfile.mkdtemp(prefix=f"nps-rate-{rate_kb}-"))
    vkey = "rate-" + os.urandom(8).hex()
    bridge = free_port()
    listen = free_port()
    web = free_port()
    echo = Echo()

    cfg = {
        "bridge_addr": f"127.0.0.1:{bridge}",
        "web_addr": f"127.0.0.1:{web}",
        "clients": [
            {"id": 1, "name": "rate-test", "vkey": vkey, "rate_limit": rate_kb}
        ],
        "tunnels": [
            {
                "id": 1,
                "name": "rate-tcp",
                "client_id": 1,
                "listen_addr": f"127.0.0.1:{listen}",
                "target_addr": f"127.0.0.1:{echo.port}",
                "enabled": True,
            }
        ],
    }
    cfg_path = run_dir / "rnps.json"
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")

    env = dict(os.environ)
    env["NPS_ADMIN_TOKEN"] = "rate-token-" + os.urandom(16).hex()
    env["RUST_LOG"] = "info"

    slog = (run_dir / "rnps.log").open("w", encoding="utf-8")
    server = subprocess.Popen(
        [server_bin, "--config", str(cfg_path)],
        stdout=slog,
        stderr=subprocess.STDOUT,
        env=env,
    )
    nlog = (run_dir / "npc.log").open("w", encoding="utf-8")
    npc = subprocess.Popen(
        [npc_bin, f"-server=127.0.0.1:{bridge}", f"-vkey={vkey}", "-type=tcp"],
        stdout=nlog,
        stderr=subprocess.STDOUT,
        env=env,
    )

    try:
        # 等 npc 上线
        import urllib.request

        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                req = urllib.request.Request(
                    f"http://127.0.0.1:{web}/api/status",
                    headers={"Authorization": f"Bearer {env['NPS_ADMIN_TOKEN']}"},
                )
                with urllib.request.urlopen(req, timeout=2) as rsp:
                    data = json.loads(rsp.read())
                if any(c.get("online") for c in data.get("clients", [])):
                    break
            except Exception:
                pass
            time.sleep(0.3)
        else:
            raise RuntimeError("npc 未上线")

        data = os.urandom(payload)
        with socket.create_connection(("127.0.0.1", listen), timeout=180) as c:
            c.settimeout(180)
            start = time.time()
            received = 0
            done = False
            sender_done = False

            def sender() -> None:
                nonlocal sender_done
                try:
                    c.sendall(data)
                    sender_done = True
                except OSError:
                    pass

            th = threading.Thread(target=sender, daemon=True)
            th.start()
            while received < payload:
                chunk = c.recv(65536)
                if not chunk:
                    break
                received += len(chunk)
            elapsed = time.time() - start
            th.join(timeout=5)
            if received != payload:
                raise RuntimeError(f"只收到 {received}/{payload} 字节")
        return elapsed
    finally:
        for p in (npc, server):
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
        slog.close()
        nlog.close()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--server-bin", required=True)
    ap.add_argument("--npc-bin", required=True)
    ap.add_argument("--payload", type=int, default=1024 * 1024)
    args = ap.parse_args()

    payload = args.payload

    print("-- 不限速（rate_limit=0）", flush=True)
    fast = run_case(args.server_bin, args.npc_bin, 0, payload)
    print(f"     耗时 {fast:.2f}s", flush=True)

    print("-- 限速 100 KB/s（rate_limit=100）", flush=True)
    slow = run_case(args.server_bin, args.npc_bin, 100, payload)
    print(f"     耗时 {slow:.2f}s", flush=True)

    mb = payload / (1024 * 1024)
    print(f"\n传输 {mb:.2f} MiB：不限速 {fast:.2f}s，限速 {slow:.2f}s，比值 {slow / max(fast, 0.001):.1f}x", flush=True)

    # 1 MiB @ 100 KB/s 理论 ≈ 10.24s；桶容量 1s 配额，故实测约 9~11s
    expected = payload / (100 * 1024)
    if slow >= expected * 0.75:
        ok(f"限速生效：{slow:.2f}s ≥ 理论 {expected:.2f}s 的 75%")
    else:
        bad(f"限速未生效：{slow:.2f}s 远小于理论 {expected:.2f}s")

    if slow > fast * 3:
        ok(f"限速与不限速有明显差异（{slow / max(fast, 0.001):.1f}x）")
    else:
        bad(f"限速与不限速差异不足（{slow / max(fast, 0.001):.1f}x），可能没生效")

    if fast < expected * 0.5:
        ok(f"不限速时无额外开销（{fast:.2f}s）")
    else:
        bad(f"不限速时也慢（{fast:.2f}s），可能有误加限制")

    print(f"\nRESULT {len(PASS)} passed, {len(FAIL)} failed", flush=True)
    return 0 if not FAIL else 1


if __name__ == "__main__":
    raise SystemExit(main())
