#!/usr/bin/env python3
"""验证 crypt / compress 子流包装与真实原版 npc 互通。

原版语义（lib/conn/conn.go:GetConn）：
    if cpt { TLS 包装 } else if snappy { snappy framed 包装 } else { 原样 }
即 crypt 优先，两者同时为 true 时 compress 被忽略。

本脚本分别验证：
  1. crypt=true        —— 数据经自签 TLS 包装后仍逐字节一致
  2. compress=true     —— 数据经 snappy framed 包装后仍逐字节一致
  3. 两者同时为 true   —— 仍能通（crypt 优先）
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
            conn.settimeout(60)
            while True:
                d = conn.recv(65536)
                if not d:
                    return
                conn.sendall(d)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


def run_case(server_bin: str, npc_bin: str, crypt: bool, compress: bool, payload: int) -> bool:
    tag = f"crypt={crypt} compress={compress}"
    run_dir = Path(tempfile.mkdtemp(prefix="nps-crypt-"))
    vkey = "c-" + os.urandom(8).hex()
    bridge, listen, web = free_port(), free_port(), free_port()
    echo = Echo()

    cfg = {
        "bridge_addr": f"127.0.0.1:{bridge}",
        "web_addr": f"127.0.0.1:{web}",
        "conf_register": True,
        "conf_listen_host": "127.0.0.1",
        "clients": [
            {
                "id": 1,
                "name": "c",
                "vkey": vkey,
                "crypt": crypt,
                "compress": compress,
            }
        ],
        "tunnels": [],
    }
    cp = run_dir / "rnps.json"
    cp.write_text(json.dumps(cfg), encoding="utf-8")

    env = dict(os.environ)
    env["NPS_ADMIN_TOKEN"] = "crypt-token-" + os.urandom(16).hex()
    env["RUST_LOG"] = "debug"

    slog = (run_dir / "rnps.log").open("w", encoding="utf-8")
    server = subprocess.Popen(
        [server_bin, "--config", str(cp)], stdout=slog, stderr=subprocess.STDOUT, env=env
    )

    # npc 侧：用命令行 + conf 文件方式开启 crypt/compress
    npc_conf = run_dir / "npc.conf"
    npc_conf.write_text(
        "\n".join(
            [
                "[common]",
                f"server_addr=127.0.0.1:{bridge}",
                "conn_type=tcp",
                f"vkey={vkey}",
                f"crypt={'true' if crypt else 'false'}",
                f"compress={'true' if compress else 'false'}",
                "",
                "[crypt-test]",
                "mode=tcp",
                f"target_addr=127.0.0.1:{echo.port}",
                f"server_port={listen}",
                "",
            ]
        ),
        encoding="utf-8",
    )
    # 必须先等服务端桥端口就绪，否则 npc 会因连接被拒而退出
    ready = False
    for _ in range(150):
        try:
            with socket.create_connection(("127.0.0.1", bridge), timeout=1):
                ready = True
                break
        except OSError:
            time.sleep(0.2)
    if not ready:
        bad(f"{tag}: 服务端桥端口未就绪")
        for p in (server,):
            if p.poll() is None:
                p.terminate()
        slog.close()
        return False

    nlog = (run_dir / "npc.log").open("w", encoding="utf-8")
    npc = subprocess.Popen(
        [npc_bin, f"-config={npc_conf}"], stdout=nlog, stderr=subprocess.STDOUT, env=env
    )

    try:
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
            bad(f"{tag}: npc 未上线（可能握手失败）")
            return False

        # npc 上线 ≠ 隧道监听器就绪：conf 注册建监听、npc 建 chan 都要时间。
        # 这里探到端口可连为止（最多 15s），否则 TLS 握手会在半就绪状态下超时。
        listen_ready = False
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", listen), timeout=1):
                    listen_ready = True
                    break
            except OSError:
                time.sleep(0.2)
        if not listen_ready:
            bad(f"{tag}: 隧道端口 {listen} 未就绪")
            return False
        # 端口刚开时 npc 侧可能还在建 mux 会话，给它一点时间
        time.sleep(1.5)

        data_bytes = os.urandom(payload)

        def transfer() -> bytes:
            with socket.create_connection(("127.0.0.1", listen), timeout=30) as c:
                c.settimeout(30)
                c.sendall(data_bytes)
                out = b""
                while len(out) < payload:
                    d = c.recv(65536)
                    if not d:
                        break
                    out += d
                return out

        # 就绪探测本身会触发一次子流建立/关闭，首次传输可能撞上隧道切换；
        # 重试最多 3 次，每次间隔 1s。
        got = b""
        last_err = None
        for attempt in range(3):
            try:
                got = transfer()
                if got == data_bytes:
                    break
            except OSError as e:
                last_err = e
            if attempt < 2:
                time.sleep(1.0)

        if not got and last_err is not None:
            bad(f"{tag}: 传输失败 {last_err}")
            return False

        if got == data_bytes:
            ok(f"{tag}: {payload} 字节逐字节一致")
            return True
        bad(f"{tag}: 数据不一致（收 {len(got)}/{payload} 字节）")
        return False

    finally:
        for p in (npc, server):
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=5)
        slog.close()
        nlog.close()
        # 等端口真正释放，避免下一个 case 撞端口/复用连接
        deadline = time.time() + 10
        while time.time() < deadline:
            busy = False
            for port in (bridge, listen, web, echo.port):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                        busy = True
                        break
                except OSError:
                    pass
            if not busy:
                break
            time.sleep(0.2)
        try:
            echo.sock.close()
        except OSError:
            pass
        time.sleep(0.5)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--server-bin", required=True)
    ap.add_argument("--npc-bin", required=True)
    ap.add_argument("--payload", type=int, default=256 * 1024)
    args = ap.parse_args()

    print("-- crypt=true（自签 TLS 包装）", flush=True)
    run_case(args.server_bin, args.npc_bin, True, False, args.payload)

    print("-- compress=true（snappy framed 包装）", flush=True)
    run_case(args.server_bin, args.npc_bin, False, True, args.payload)

    print("-- 两者同时 true（crypt 优先，与原版 if/else if 一致）", flush=True)
    run_case(args.server_bin, args.npc_bin, True, True, args.payload)

    print("-- 基线：两者都 false", flush=True)
    run_case(args.server_bin, args.npc_bin, False, False, args.payload)

    print(f"\nRESULT {len(PASS)} passed, {len(FAIL)} failed", flush=True)
    return 0 if not FAIL else 1


if __name__ == "__main__":
    raise SystemExit(main())
