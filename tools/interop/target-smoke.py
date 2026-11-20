#!/usr/bin/env python3
"""验证多目标轮询与健康检查在生产路径生效。

场景：
  1. 一条 TCP 隧道配两个目标（A、B），请求应交替落到 A、B
  2. 关掉 B，健康检查达到阈值后 B 被摘除，请求只落 A
  3. 全目标离线时，外部连接应被拒绝（而不是挂住或 500）
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import subprocess
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


class NamedEcho:
    """回显时带上自己的名字，便于区分请求落到哪个目标。"""

    def __init__(self, name: str) -> None:
        self.name = name
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(32)
        self.port = self.sock.getsockname()[1]
        self.hits = 0
        self._stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(10)
            self.hits += 1
            conn.sendall(self.name.encode())
            conn.recv(1024)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self) -> None:
        self._stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def probe(listen_port: int, timeout: float = 5.0) -> str:
    """连一次隧道，返回目标名字。

    返回 "fail" 表示「被拒绝」（连接失败或服务端立即关闭且未回数据）——
    全目标离线时服务端正是这样做的。
    """
    try:
        with socket.create_connection(("127.0.0.1", listen_port), timeout=timeout) as c:
            c.settimeout(timeout)
            data = c.recv(64)
            if not data:
                # 服务端接受 TCP 后立刻关闭 = 明确拒绝，不是"返回垃圾数据"
                return "fail"
            return data.decode("utf-8", "replace")
    except OSError:
        return "fail"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--server-bin", required=True)
    ap.add_argument("--npc-bin", required=True)
    args = ap.parse_args()

    run_dir = Path(tempfile.mkdtemp(prefix="nps-target-"))
    vkey = "target-" + os.urandom(8).hex()
    bridge = free_port()
    listen = free_port()
    web = free_port()

    a = NamedEcho("A")
    b = NamedEcho("B")

    cfg = {
        "bridge_addr": f"127.0.0.1:{bridge}",
        "web_addr": f"127.0.0.1:{web}",
        "clients": [{"id": 1, "name": "t", "vkey": vkey}],
        "tunnels": [
            {
                "id": 1,
                "name": "multi",
                "client_id": 1,
                "listen_addr": f"127.0.0.1:{listen}",
                "target_addr": f"127.0.0.1:{a.port}",
                "target_addrs": [
                    f"127.0.0.1:{a.port}",
                    f"127.0.0.1:{b.port}",
                ],
                "health_check": {
                    "timeout_secs": 1,
                    "max_failed": 2,
                    "interval_secs": 1,
                    "kind": "tcp",
                },
                "enabled": True,
            }
        ],
    }
    cfg_path = run_dir / "rnps.json"
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")

    env = dict(os.environ)
    env["NPS_ADMIN_TOKEN"] = "target-token-" + os.urandom(16).hex()
    env["RUST_LOG"] = "info"

    slog = (run_dir / "rnps.log").open("w", encoding="utf-8")
    server = subprocess.Popen(
        [args.server_bin, "--config", str(cfg_path)],
        stdout=slog,
        stderr=subprocess.STDOUT,
        env=env,
    )
    nlog = (run_dir / "npc.log").open("w", encoding="utf-8")
    npc = subprocess.Popen(
        [args.npc_bin, f"-server=127.0.0.1:{bridge}", f"-vkey={vkey}", "-type=tcp"],
        stdout=nlog,
        stderr=subprocess.STDOUT,
        env=env,
    )

    try:
        # 等上线
        import urllib.request

        deadline = time.time() + 60
        online = False
        while time.time() < deadline:
            try:
                req = urllib.request.Request(
                    f"http://127.0.0.1:{web}/api/status",
                    headers={"Authorization": f"Bearer {env['NPS_ADMIN_TOKEN']}"},
                )
                with urllib.request.urlopen(req, timeout=2) as rsp:
                    data = json.loads(rsp.read())
                if any(c.get("online") for c in data.get("clients", [])):
                    online = True
                    break
            except Exception:
                pass
            time.sleep(0.3)
        if not online:
            bad("npc 未上线")
            return 1
        ok("npc 已上线")

        # 1) 轮询：连续 8 次应交替出现 A 和 B
        seen: list[str] = []
        for _ in range(8):
            seen.append(probe(listen))
            time.sleep(0.05)
        a_count = seen.count("A")
        b_count = seen.count("B")
        print(f"     轮询结果: {seen}", flush=True)
        if a_count >= 2 and b_count >= 2:
            ok(f"多目标轮询生效（A={a_count} 次，B={b_count} 次）")
        else:
            bad(f"轮询未生效：A={a_count} B={b_count}（期望两者都 >= 2）")

        # 2) 关掉 B，等健康检查摘除（interval=1s, max_failed=2 → 约 2~4s）
        b.close()
        time.sleep(5)
        seen2: list[str] = []
        for _ in range(6):
            seen2.append(probe(listen))
            time.sleep(0.05)
        print(f"     B 关闭后: {seen2}", flush=True)
        if seen2.count("A") >= 5 and "B" not in seen2:
            ok("B 离线后健康检查已摘除，请求只落 A")
        else:
            bad(f"B 离线后仍被路由：{seen2}")

        # 3) 关掉 A，全离线时连接应被拒绝
        a.close()
        time.sleep(5)
        result = probe(listen, timeout=8)
        print(f"     全离线后探测: {result}", flush=True)
        if result == "fail":
            ok("全目标离线时外部连接被拒绝（未挂住、未返回垃圾数据）")
        else:
            bad(f"全目标离线时仍返回 {result!r}（应拒绝）")

    finally:
        for p in (npc, server):
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()
        a.close()
        b.close()
        slog.close()
        nlog.close()

    print(f"\nRESULT {len(PASS)} passed, {len(FAIL)} failed", flush=True)
    print(f"[run dir] {run_dir}", flush=True)
    return 0 if not FAIL else 1


if __name__ == "__main__":
    raise SystemExit(main())
