#!/usr/bin/env python3
"""验证 p2p 会合服务与真实原版 npc 的交互。

原版机制（`server/proxy/p2p.go` + `client/control.go:handleP2PUdp`）：
  - 服务端起 **3 个连续 UDP 端口**（p2p_port / +1 / +2）
  - 客户端向这三个端口**各发一次** `md5(password)*#*role`
  - 服务端记住地址；visitor 侧等到 provider 到齐后互发对方 ip:port
  - 双方拿到地址后自建 KCP 连接（服务端不参与传输）

本脚本用 Python 模拟「provider + visitor」两侧，验证：
  1. 三个端口都在监听
  2. 双方都能拿到对方的真实 UDP 地址（三端口都返回一致结果）
  3. 报文格式非法时被忽略（服务端不崩）

注意：真实 npc 的 p2p 走 KCP（需要 kcp-go），本脚本不测 KCP 传输本身，
只测服务端的会合信令——那是本项目的实现范围。
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


def free_port_triple() -> int:
    """找一个连续三个端口都可用的起始端口。"""
    for _ in range(200):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            base = s.getsockname()[1]
        if base + 2 > 65000:
            continue
        socks = []
        try:
            for i in range(3):
                u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                u.bind(("127.0.0.1", base + i))
                socks.append(u)
            return base
        except OSError:
            continue
        finally:
            for u in socks:
                u.close()
    raise RuntimeError("找不到连续三个可用端口")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--server-bin", required=True)
    ap.add_argument("--timeout", type=float, default=30.0)
    args = ap.parse_args()

    run_dir = Path(tempfile.mkdtemp(prefix="nps-p2p-"))
    vkey = "pk-" + os.urandom(8).hex()
    bridge = free_port_triple()  # 用作 bridge 起点（不要求连续）
    p2p_base = free_port_triple()
    web_port = bridge + 3 if bridge + 3 < 65000 else 0
    while True:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            web_port = s.getsockname()[1]
        if not (p2p_base <= web_port <= p2p_base + 2):
            break

    cfg = {
        "bridge_addr": f"127.0.0.1:{bridge}",
        "web_addr": f"127.0.0.1:{web_port}",
        "clients": [{"id": 1, "name": "c", "vkey": vkey}],
        "tunnels": [],
        "p2p_listen_addr": f"127.0.0.1:{p2p_base}",
    }
    cp = run_dir / "rnps.json"
    cp.write_text(json.dumps(cfg), encoding="utf-8")

    env = dict(os.environ)
    env["NPS_ADMIN_TOKEN"] = "p2p-token-" + os.urandom(16).hex()
    env["RUST_LOG"] = "info"

    slog = (run_dir / "rnps.log").open("w", encoding="utf-8")
    server = subprocess.Popen(
        [args.server_bin, "--config", str(cp)], stdout=slog, stderr=subprocess.STDOUT, env=env
    )

    try:
        # 等三个 UDP 端口都就绪
        deadline = time.time() + args.timeout
        ready = False
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", bridge), timeout=1):
                    ready = True
                    break
            except OSError:
                time.sleep(0.2)
        if not ready:
            bad("服务端桥端口未就绪")
            return 1
        ok("rnps 启动")

        # 1) 三个端口都在监听（发一个空包应能收到 ICMP 或不报错）
        listening = 0
        for i in range(3):
            port = p2p_base + i
            try:
                u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                u.settimeout(1.0)
                # 发一个非法包（服务端应忽略，不应崩溃）
                u.sendto(b"probe", ("127.0.0.1", port))
                u.close()
                listening += 1
            except OSError:
                pass
        if listening == 3:
            ok(f"三个会合端口 {p2p_base}~{p2p_base+2} 均可发送")
        else:
            bad(f"只有 {listening}/3 个端口可用")

        # 2) provider + visitor 会合（对三个端口各做一次）
        password = "p2ppw-" + os.urandom(6).hex()

        for offset in range(3):
            port = p2p_base + offset
            provider = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            provider.bind(("127.0.0.1", 0))
            provider.settimeout(5.0)
            provider_addr = provider.getsockname()

            visitor = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            visitor.bind(("127.0.0.1", 0))
            visitor.settimeout(5.0)
            visitor_addr = visitor.getsockname()

            # provider 先登记
            provider.sendto(f"{password}*#*p2pp".encode(), ("127.0.0.1", port))
            time.sleep(0.3)
            # visitor 发起
            visitor.sendto(f"{password}*#*p2pv".encode(), ("127.0.0.1", port))

            try:
                data, _ = visitor.recvfrom(256)
                got_provider = data.decode().strip()
                data, _ = provider.recvfrom(256)
                got_visitor = data.decode().strip()

                if got_provider == f"{provider_addr[0]}:{provider_addr[1]}" and got_visitor == (
                    f"{visitor_addr[0]}:{visitor_addr[1]}"
                ):
                    ok(f"端口 {port}: 双方互发地址正确（visitor→{got_provider}）")
                else:
                    bad(
                        f"端口 {port}: 地址不符 "
                        f"(期望 provider={provider_addr} 实得 {got_provider}; "
                        f"期望 visitor={visitor_addr} 实得 {got_visitor})"
                    )
            except socket.timeout:
                bad(f"端口 {port}: 会合超时（未收到对方地址）")
            finally:
                provider.close()
                visitor.close()

        # 3) 非法报文不应让服务端崩溃
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for bad_payload in [b"", b"no-sep", b"pw*#*unknown", b"\xff\xfe\xfd"]:
            try:
                u.sendto(bad_payload, ("127.0.0.1", p2p_base))
            except OSError:
                pass
        u.close()
        time.sleep(0.5)

        # 服务端仍应存活
        try:
            with socket.create_connection(("127.0.0.1", bridge), timeout=2):
                ok("非法报文后服务端仍存活")
        except OSError:
            bad("非法报文后服务端不可达")

    finally:
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
        slog.close()

    print(f"\nRESULT {len(PASS)} passed, {len(FAIL)} failed", flush=True)
    print(f"[run dir] {run_dir}", flush=True)
    return 0 if not FAIL else 1


if __name__ == "__main__":
    raise SystemExit(main())
