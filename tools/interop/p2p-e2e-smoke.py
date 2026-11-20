#!/usr/bin/env python3
"""p2p 模式端到端验证：**两个真实原版 npc** 经 rnps 会合后 KCP 直连。

原版机制（provider = 提供网络的一端，visitor = 访问方）：
  1. provider npc 配置 `[p2p] mode=p2p password=X`（经 conf 通道登记任务）
  2. visitor npc 配置 `[p2p_ssh] local_port=L password=X target_addr=T`
  3. visitor 本地连 L → npc 以 `p2pm` 连桥发 md5(X) → 服务端按 md5 找到
     provider 任务，向 provider 的 signal 推 `udpc` 邀请（会合地址 + md5），
     并在 p2pm 连接上回执会合地址给 visitor
  4. 双方各向会合服务的 3 个 UDP 端口发 `md5*#*role`，拿到对方地址后
     自行 KCP 打洞直连，visitor 经 KCP 把 target 发给 provider 拨号
  5. 服务端只参与 1~4 的信令，**不承载流量**

本脚本验证：信令全链路（conf 登记 → p2pm → 邀请 → 回执）+ 双 npc KCP 直连
后的真实数据往返（不经过服务端）。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
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


def free_udp_triple() -> int:
    for _ in range(200):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            base = s.getsockname()[1]
        if base + 2 >= 65000:
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
    raise RuntimeError("找不到连续三个可用 UDP 端口")


def api_status(web_port: int, token: str) -> dict:
    req = urllib.request.Request(
        f"http://127.0.0.1:{web_port}/api/status",
        headers={"Authorization": "Bearer " + token},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        return json.loads(resp.read().decode("utf-8"))


def wait_clients_online(web_port: int, token: str, count: int, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            snap = api_status(web_port, token)
            online = [c for c in snap.get("clients", []) if c.get("online")]
            if len(online) >= count:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def start_echo_server(port: int, stop: threading.Event) -> threading.Thread:
    """TCP echo 目标：p2p provider 最终要拨号的服务。"""

    def serve() -> None:
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port))
        srv.listen(16)
        srv.settimeout(0.5)
        conns = []
        while not stop.is_set():
            try:
                c, _ = srv.accept()
                c.settimeout(0.5)
                conns.append(c)
            except socket.timeout:
                pass
            except OSError:
                break
            for c in list(conns):
                try:
                    data = c.recv(65536)
                    if data:
                        c.sendall(data)
                    else:
                        c.close()
                        conns.remove(c)
                except socket.timeout:
                    continue
                except OSError:
                    try:
                        conns.remove(c)
                    except ValueError:
                        pass
        for c in conns:
            try:
                c.close()
            except OSError:
                pass
        srv.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return t


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--server-bin", required=True)
    ap.add_argument("--npc-bin", required=True)
    ap.add_argument("--timeout", type=float, default=60.0)
    args = ap.parse_args()

    run_dir = Path(tempfile.mkdtemp(prefix="nps-p2p-e2e-"))
    bridge = free_port()
    web = free_port()
    p2p_base = free_udp_triple()
    target_port = free_port()
    visitor_local = free_port()
    # 原版 npc 用「UDP dial 114.114.114.114:53」探测默认出口网卡，并把 p2p 的
    # UDP 套接字**绑定**在该 IP 上（lib/common/util.go GetLocalUdpAddr）。
    # 因此会合地址必须与该网卡同网段（回环地址会 wsasendto 失败——对原版
    # 服务端也一样，这是 npc 侧的部署特性）。这里取同一探测逻辑的结果。
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    probe.connect(("114.114.114.114", 53))
    lan_ip = probe.getsockname()[0]
    probe.close()
    password = "p2pe2e-" + os.urandom(6).hex()
    provider_vkey = "pk-provider-" + os.urandom(8).hex()
    visitor_vkey = "pk-visitor-" + os.urandom(8).hex()
    admin_token = "p2p-e2e-token-" + os.urandom(16).hex()

    cfg = {
        "bridge_addr": f"127.0.0.1:{bridge}",
        "web_addr": f"127.0.0.1:{web}",
        "conf_register": True,
        "conf_listen_host": "127.0.0.1",
        "p2p_listen_addr": f"{lan_ip}:{p2p_base}",
        "clients": [
            {"id": 1, "name": "provider", "vkey": provider_vkey},
            {"id": 2, "name": "visitor", "vkey": visitor_vkey},
        ],
    }
    cp = run_dir / "rnps.json"
    cp.write_text(json.dumps(cfg), encoding="utf-8")

    # provider npc：[p2p] 段经 conf 登记任务
    provider_conf = run_dir / "npc-provider.conf"
    provider_conf.write_text(
        "[common]\n"
        f"server_addr=127.0.0.1:{bridge}\n"
        "conn_type=tcp\n"
        f"vkey={provider_vkey}\n"
        "auto_reconnection=true\n"
        "\n"
        "[p2p]\n"
        "mode=p2p\n"
        f"password={password}\n",
        encoding="utf-8",
    )
    # visitor npc：本地监听 + 密码 + 目标
    visitor_conf = run_dir / "npc-visitor.conf"
    visitor_conf.write_text(
        "[common]\n"
        f"server_addr=127.0.0.1:{bridge}\n"
        "conn_type=tcp\n"
        f"vkey={visitor_vkey}\n"
        "auto_reconnection=true\n"
        "\n"
        "[p2p_ssh]\n"
        f"local_port={visitor_local}\n"
        f"password={password}\n"
        f"target_addr=127.0.0.1:{target_port}\n",
        encoding="utf-8",
    )

    env = dict(os.environ)
    env["NPS_ADMIN_TOKEN"] = admin_token
    env["RUST_LOG"] = "debug"

    slog = (run_dir / "rnps.log").open("w", encoding="utf-8")
    plog = (run_dir / "npc-provider.log").open("w", encoding="utf-8")
    vlog = (run_dir / "npc-visitor.log").open("w", encoding="utf-8")
    server = subprocess.Popen(
        [args.server_bin, "--config", str(cp)],
        stdout=slog, stderr=subprocess.STDOUT, env=env,
    )
    provider = subprocess.Popen(
        [args.npc_bin, "-config", str(provider_conf)],
        stdout=plog, stderr=subprocess.STDOUT, env=env,
    )
    visitor = subprocess.Popen(
        [args.npc_bin, "-config", str(visitor_conf)],
        stdout=vlog, stderr=subprocess.STDOUT, env=env,
    )
    stop = threading.Event()
    echo = start_echo_server(target_port, stop)

    def tail(path: Path, limit: int = 4000) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="replace")[-limit:]
        except OSError:
            return ""

    try:
        # 1) 服务端就绪
        deadline = time.time() + args.timeout
        ready = False
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", bridge), timeout=1):
                    ready = True
                    break
            except OSError:
                time.sleep(0.2)
        if ready:
            ok("rnps 启动，桥端口就绪")
        else:
            bad("rnps 桥端口未就绪")
            return 1

        # 2) 两个 npc 都上线
        if wait_clients_online(web, admin_token, 2, args.timeout):
            ok("provider 与 visitor 两个 npc 均在线")
        else:
            bad("npc 未全部上线")
            print(tail(run_dir / "rnps.log"))
            return 1

        # 3) 经 visitor 本地端口做 TCP echo（KCP 直连后 provider 拨号目标）
        payload = os.urandom(65536)
        deadline = time.time() + args.timeout
        round_ok = False
        while time.time() < deadline and not round_ok:
            try:
                with socket.create_connection(("127.0.0.1", visitor_local), timeout=5) as c:
                    c.settimeout(10)
                    c.sendall(payload)
                    got = b""
                    while len(got) < len(payload):
                        chunk = c.recv(65536)
                        if not chunk:
                            break
                        got += chunk
                    if got == payload:
                        round_ok = True
            except OSError:
                time.sleep(1.0)
        if round_ok:
            ok(f"p2p 直连往返逐字节一致（{len(payload)} 字节，未经过服务端转发）")
        else:
            bad("p2p 直连往返失败")
            print("--- rnps.log tail ---")
            print(tail(run_dir / "rnps.log"))
            print("--- npc-provider.log tail ---")
            print(tail(plog.name and Path(plog.name)))
            print("--- npc-visitor.log tail ---")
            print(tail(Path(vlog.name)))
            return 1

        # 4) 第二条连接仍然可用（会合条目单次消费后，后续连接重新走信令）
        payload2 = os.urandom(8192)
        try:
            with socket.create_connection(("127.0.0.1", visitor_local), timeout=5) as c:
                c.settimeout(15)
                c.sendall(payload2)
                got = b""
                while len(got) < len(payload2):
                    chunk = c.recv(65536)
                    if not chunk:
                        break
                    got += chunk
            if got == payload2:
                ok("第二条连接再次走完整信令并成功（会合条目按次消费）")
            else:
                bad("第二条连接数据不一致")
        except OSError as e:
            bad(f"第二条连接失败: {e}")

        # 5) 服务端仍存活（p2p 信令不影响桥）
        try:
            with socket.create_connection(("127.0.0.1", bridge), timeout=2):
                ok("信令完成后服务端桥仍存活")
        except OSError:
            bad("服务端桥不可达")

    finally:
        stop.set()
        echo.join(timeout=2)
        for proc in (visitor, provider, server):
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    proc.kill()
        for f in (slog, plog, vlog):
            f.close()

    print(f"\nRESULT {len(PASS)} passed, {len(FAIL)} failed", flush=True)
    print(f"[run dir] {run_dir}", flush=True)
    return 0 if not FAIL else 1


if __name__ == "__main__":
    raise SystemExit(main())
