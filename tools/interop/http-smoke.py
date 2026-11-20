#!/usr/bin/env python3
"""HTTP 域名代理联调验证：真实 Go npc ⇄ Rust HTTP 站点。

这里 **不用 rnps.exe**：`server.rs` 尚未接线 HTTP 站点（由父代理完成）。
脚本启动 `cargo test` 里的 `real_npc_http_harness`（一个真实的 Rust 服务端：
Bridge + HttpSiteServer），再启动真实 `npc.exe` 通过真实桥/mux 接入，
所有 HTTP / WebSocket 断言都由本脚本用标准库完成。

覆盖：
  * Host 匹配（大小写、带端口）、路径前缀最长匹配
  * GET / POST（Content-Length 与 chunked 请求体）
  * >1 MiB 大响应、chunked 响应、Connection: close
  * Keep-Alive：同一 TCP 连接两个请求（每次一个新子流）
  * WebSocket 升级 + 双向消息
  * 未匹配域名 404、npc 离线 502

运行：
    python -I http-smoke.py [--npc-bin <npc.exe>] [--rust-dir <rust>]

退出码：0 全部通过；1 有失败；2 本地文件/环境问题。
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


# ---------------------------------------------------------------------------
# 目标 HTTP 服务（Python 标准库，支持 CL / chunked / WebSocket）
# ---------------------------------------------------------------------------
class TargetHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    flavor = "unknown"

    def log_message(self, *args):  # 静音
        pass

    # ---- 读请求体 ----
    def _read_body(self) -> bytes:
        te = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in te:
            out = bytearray()
            while True:
                line = self.rfile.readline().strip()
                if not line:
                    break
                size = int(line.split(b";")[0], 16)
                if size == 0:
                    while True:
                        trailer = self.rfile.readline()
                        if trailer in (b"\r\n", b"\n", b""):
                            break
                    break
                out += self.rfile.read(size)
                self.rfile.read(2)  # chunk 末尾 CRLF
            return bytes(out)
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    def _send(self, body: bytes, content_type="text/plain", extra=None):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    # ---- WebSocket ----
    def _websocket(self):
        key = self.headers.get("Sec-WebSocket-Key", "")
        accept = base64.b64encode(
            hashlib.sha1((key + WS_GUID).encode()).digest()
        ).decode()
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        self.wfile.flush()

        sock = self.connection
        while True:
            header = sock.recv(2)
            if len(header) < 2:
                return
            first, second = header[0], header[1]
            length = second & 0x7F
            if length == 126:
                length = struct.unpack("!H", sock.recv(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", sock.recv(8))[0]
            mask = sock.recv(4) if second & 0x80 else b""
            payload = b""
            while len(payload) < length:
                chunk = sock.recv(length - len(payload))
                if not chunk:
                    return
                payload += chunk
            if mask:
                payload = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
            opcode = first & 0x0F
            if opcode == 0x8:  # close
                return
            if opcode in (0x1, 0x2):
                self._ws_send(opcode, payload)

    def _ws_send(self, opcode: int, payload: bytes):
        header = bytes([0x80 | opcode])
        if len(payload) < 126:
            header += bytes([len(payload)])
        elif len(payload) < 1 << 16:
            header += bytes([126]) + struct.pack("!H", len(payload))
        else:
            header += bytes([127]) + struct.pack("!Q", len(payload))
        self.connection.sendall(header + payload)

    # ---- 路由 ----
    def do_GET(self):
        if (self.headers.get("Upgrade") or "").lower() == "websocket":
            self._websocket()
            self.close_connection = True
            return
        path = self.path.split("?")[0]
        if path in ("/", "/echo"):
            self._send(f"hello-from-{self.flavor}".encode())
        elif path == "/headers":
            lines = [f"{k}: {v}" for k, v in self.headers.items()]
            self._send("\n".join(lines).encode())
        elif path == "/big":
            self._send(b"b" * (2 * 1024 * 1024))
        elif path == "/chunked":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for part in (b"alpha-", b"beta-", b"gamma"):
                self.wfile.write(b"%x\r\n%s\r\n" % (len(part), part))
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        elif path == "/close":
            body = b"bye\n"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            self.close_connection = True
        elif path.startswith("/api"):
            self._send(f"api-from-{self.flavor}".encode())
        else:
            body = b"target-404"
            self.send_response(404)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_POST(self):
        body = self._read_body()
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Echo-Len", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def start_target(flavor: str):
    class Handler(TargetHandler):
        pass
    Handler.flavor = flavor
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


# ---------------------------------------------------------------------------
# 极简 HTTP 客户端（raw socket，便于观察 chunked / keep-alive）
# ---------------------------------------------------------------------------
def read_head(sock: socket.socket) -> tuple[bytes, dict[str, str], bytes]:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("连接在响应头前关闭")
        buf += chunk
    head, rest = buf.split(b"\r\n\r\n", 1)
    headers = {}
    for line in head.split(b"\r\n")[1:]:
        if b":" in line:
            name, value = line.split(b":", 1)
            headers[name.decode().strip().lower()] = value.decode().strip()
    return head, headers, rest


def read_body(sock: socket.socket, headers: dict[str, str], initial: bytes) -> bytes:
    if "chunked" in headers.get("transfer-encoding", "").lower():
        data = initial
        out = bytearray()
        while True:
            while b"\r\n" not in data:
                data += sock.recv(4096)
            line, data = data.split(b"\r\n", 1)
            size = int(line.split(b";")[0], 16)
            if size == 0:
                while b"\r\n" not in data:
                    data += sock.recv(4096)
                return bytes(out)
            while len(data) < size + 2:
                data += sock.recv(4096)
            out += data[:size]
            data = data[size + 2:]
    else:
        length = int(headers.get("content-length", "0"))
        data = initial
        while len(data) < length:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
        return data[:length]


def request(addr, host_header, method="GET", path="/", body: bytes | None = None,
            chunked=False, timeout=20):
    sock = socket.create_connection(addr, timeout=timeout)
    sock.settimeout(timeout)
    head = [f"{method} {path} HTTP/1.1", f"Host: {host_header}"]
    if body is not None:
        if chunked:
            head.append("Transfer-Encoding: chunked")
            payload = b""
            for i in range(0, len(body), 16384):
                part = body[i:i + 16384]
                payload += b"%x\r\n%s\r\n" % (len(part), part)
            payload += b"0\r\n\r\n"
        else:
            head.append(f"Content-Length: {len(body)}")
            payload = body
    else:
        payload = b""
    head.append("Connection: keep-alive")
    sock.sendall(("\r\n".join(head) + "\r\n\r\n").encode() + payload)
    raw_head, headers, rest = read_head(sock)
    status = int(raw_head.split(b" ")[1])
    data = read_body(sock, headers, rest)
    return sock, status, headers, data


def stop_socket(sock):
    try:
        sock.close()
    except OSError:
        pass


# ---------------------------------------------------------------------------
# 检查器
# ---------------------------------------------------------------------------
class Checks:
    def __init__(self):
        self.items = []

    def ok(self, name, detail=""):
        self.items.append((True, name, detail))
        print(f"PASS  {name}" + (f"  [{detail}]" if detail else ""))

    def fail(self, name, detail=""):
        self.items.append((False, name, detail))
        print(f"FAIL  {name}" + (f"  [{detail}]" if detail else ""))

    def check(self, cond, name, detail=""):
        if cond:
            self.ok(name, detail)
        else:
            self.fail(name, detail)
        return cond

    @property
    def failed(self):
        return [i for i in self.items if not i[0]]


def curl(checks, addr, host, name, path="/", method="GET", body=None, chunked=False):
    try:
        sock, status, headers, data = request(
            addr, host, method=method, path=path, body=body, chunked=chunked)
        stop_socket(sock)
        return status, headers, data
    except Exception as exc:  # noqa: BLE001
        checks.fail(name, f"请求异常: {exc}")
        return None, {}, b""


# ---------------------------------------------------------------------------
# WebSocket 客户端
# ---------------------------------------------------------------------------
def websocket_echo(checks, addr, host, count=3):
    sock = socket.create_connection(addr, timeout=15)
    sock.settimeout(15)
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET /ws HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n"
        f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n\r\n"
    )
    sock.sendall(req.encode())
    head, headers, rest = read_head(sock)
    status = int(head.split(b" ")[1])
    if status != 101:
        checks.fail("WebSocket 握手返回 101", f"status={status} head={head[:80]!r}")
        stop_socket(sock)
        return
    expected = base64.b64encode(
        hashlib.sha1((key + WS_GUID).encode()).digest()
    ).decode()
    checks.check(headers.get("sec-websocket-accept") == expected,
                 "WebSocket 握手 Sec-WebSocket-Accept 正确")
    checks.ok("WebSocket 升级返回 101")

    buf = rest

    def recv_frame():
        nonlocal buf
        while len(buf) < 2:
            buf += sock.recv(4096)
        first, second = buf[0], buf[1]
        length = second & 0x7F
        offset = 2
        if length == 126:
            while len(buf) < 4:
                buf += sock.recv(4096)
            length = struct.unpack("!H", buf[2:4])[0]
            offset = 4
        elif length == 127:
            while len(buf) < 10:
                buf += sock.recv(4096)
            length = struct.unpack("!Q", buf[2:10])[0]
            offset = 10
        while len(buf) < offset + length:
            buf += sock.recv(4096)
        payload = buf[offset:offset + length]
        buf = buf[offset + length:]
        return first & 0x0F, payload

    def send_text(text: str):
        payload = text.encode()
        mask = os.urandom(4)
        masked = bytes(c ^ mask[i % 4] for i, c in enumerate(payload))
        sock.sendall(bytes([0x81, 0x80 | len(payload)]) + mask + masked)

    ok = True
    for i in range(count):
        message = f"ws-message-{i}"
        send_text(message)
        opcode, payload = recv_frame()
        if opcode != 0x1 or payload.decode(errors="replace") != message:
            checks.fail(f"WebSocket 第 {i} 条消息回显", f"opcode={opcode} payload={payload!r}")
            ok = False
            break
    if ok:
        checks.ok("WebSocket 双向消息", f"{count} 条消息原样回显")
    stop_socket(sock)


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def wait_until(fn, timeout, interval=0.2):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            if fn():
                return True, None
        except Exception as exc:  # noqa: BLE001
            last = exc
        time.sleep(interval)
    return False, last


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--npc-bin", default=None)
    parser.add_argument("--rust-dir", default=None)
    parser.add_argument("--domain", default="test.local")
    parser.add_argument("--timeout", type=float, default=60)
    args = parser.parse_args()

    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parents[1]
    npc_bin = Path(args.npc_bin) if args.npc_bin else script_dir / "bin" / "npc.exe"
    rust_dir = Path(args.rust_dir) if args.rust_dir else repo_root / "rust"

    if not npc_bin.is_file():
        print(f"ERROR: 找不到真实 npc: {npc_bin}", file=sys.stderr)
        return 2
    if not (rust_dir / "Cargo.toml").is_file():
        print(f"ERROR: 找不到 Rust 工程: {rust_dir}", file=sys.stderr)
        return 2

    run_dir = script_dir / "logs" / time.strftime("http-smoke-%Y%m%d-%H%M%S")
    run_dir.mkdir(parents=True, exist_ok=True)
    ready_file = run_dir / "harness.json"
    stop_file = run_dir / "harness.stop"

    checks = Checks()
    main_target = start_target("main-target")
    api_target = start_target("api-target")
    main_port = main_target.server_address[1]
    api_port = api_target.server_address[1]

    vkey = secrets_token()
    env = dict(os.environ)
    env.update({
        "NPS_HTTP_HARNESS_VKEY": vkey,
        "NPS_HTTP_HARNESS_DOMAIN": args.domain,
        "NPS_HTTP_HARNESS_TARGET": f"127.0.0.1:{main_port}",
        "NPS_HTTP_HARNESS_ROUTE_PREFIX": "/api",
        "NPS_HTTP_HARNESS_ROUTE_TARGET": f"127.0.0.1:{api_port}",
        "NPS_HTTP_HARNESS_READY_FILE": str(ready_file),
        "NPS_HTTP_HARNESS_STOP_FILE": str(stop_file),
    })
    env.pop("RUST_LOG", None)

    harness_log = open(run_dir / "harness.log", "wb")
    harness = subprocess.Popen(
        ["cargo", "test", "-p", "nps-server", "--test", "http_site", "--",
         "--ignored", "--exact", "real_npc_http_harness", "--nocapture",
         "--test-threads=1"],
        cwd=str(rust_dir), env=env, stdout=harness_log, stderr=subprocess.STDOUT,
    )
    npc = None
    npc_log = None
    try:
        ok, err = wait_until(lambda: ready_file.is_file(), args.timeout * 3)
        if not ok:
            print("ERROR: Rust 服务端宿主未就绪（见 harness.log）", file=sys.stderr)
            return 2
        ready = json.loads(ready_file.read_text(encoding="utf-8"))
        bridge_addr = parse_addr(ready["bridge_addr"])
        http_addr = parse_addr(ready["http_addr"])
        print(f"harness ready: bridge={ready['bridge_addr']} http={ready['http_addr']}")
        print(f"targets: main=127.0.0.1:{main_port} api=127.0.0.1:{api_port}")
        print(f"npc: {npc_bin}")

        # 真实 npc 接入（无 config：站点由服务端配置）
        npc_log = open(run_dir / "npc.log", "wb")
        npc_env = {k: v for k, v in os.environ.items() if k != "NPS_ADMIN_TOKEN"}
        npc = subprocess.Popen(
            [str(npc_bin), f"-server={ready['bridge_addr']}", f"-vkey={vkey}",
             "-type=tcp", "-log=stdout", "-debug=true", "-log_level=3"],
            env=npc_env, stdout=npc_log, stderr=subprocess.STDOUT,
        )

        # 等 npc 上线并被 HTTP 站点用到（首次请求成功即视为通）
        def online():
            sock, status, _, data = request(http_addr, args.domain, timeout=5)
            stop_socket(sock)
            return status == 200 and data == b"hello-from-main-target"

        ok, err = wait_until(online, args.timeout)
        if not ok:
            checks.fail("真实 npc 接入并转发首个请求", f"last={err}")
            print("---- npc.log 尾部 ----")
            print(tail(run_dir / "npc.log"))
            print("---- harness.log 尾部 ----")
            print(tail(run_dir / "harness.log"))
            return 1
        checks.ok("真实 npc 接入并转发首个请求")

        # 1) Host 匹配：大小写 / 带端口
        for host_header, label in [(args.domain, "Host 精确匹配"),
                                   (args.domain.upper(), "Host 大小写不敏感"),
                                   (args.domain + ":1234", "Host 带端口仍匹配")]:
            status, _, body = curl(checks, http_addr, host_header, label)
            checks.check(status == 200 and body == b"hello-from-main-target",
                         label, f"status={status} body={body[:40]!r}")

        # 2) 请求头透传（Host 原样到达目标）
        status, _, body = curl(checks, http_addr, args.domain, "请求头透传", "/headers")
        checks.check(status == 200 and b"Host:" in body,
                     "请求头透传到目标", body.decode(errors="replace")[:120])

        # 3) POST 64 KiB（Content-Length）
        payload = bytes(range(256)) * 256
        status, headers, body = curl(
            checks, http_addr, args.domain, "POST 64KiB",
            path="/echo", method="POST", body=payload)
        checks.check(status == 200 and body == payload,
                     "POST 64KiB 请求体原样转发",
                     f"status={status} len={len(body)}")

        # 4) POST chunked
        status, _, body = curl(
            checks, http_addr, args.domain, "POST chunked",
            path="/echo", method="POST", body=b"chunked-body-" * 1000, chunked=True)
        checks.check(status == 200 and body == b"chunked-body-" * 1000,
                     "chunked 请求体原样转发", f"status={status} len={len(body)}")

        # 5) 大响应（2 MiB）
        sock, status, headers, body = request(http_addr, args.domain, path="/big", timeout=60)
        stop_socket(sock)
        checks.check(status == 200 and len(body) == 2 * 1024 * 1024 and set(body) == {ord("b")},
                     "2 MiB 响应完整转发", f"len={len(body)}")

        # 6) chunked 响应
        sock, status, headers, body = request(http_addr, args.domain, path="/chunked")
        stop_socket(sock)
        checks.check(status == 200
                     and headers.get("transfer-encoding", "").lower() == "chunked"
                     and body == b"alpha-beta-gamma",
                     "chunked 响应原样转发",
                     f"te={headers.get('transfer-encoding')} body={body!r}")

        # 7) 路径前缀最长匹配
        status, _, body = curl(checks, http_addr, args.domain, "路径前缀匹配", "/api/demo")
        checks.check(status == 200 and body == b"api-from-api-target",
                     "路径前缀路由到第二目标", f"status={status} body={body!r}")

        # 8) Keep-Alive：同一 TCP 连接两个请求
        sock = socket.create_connection(http_addr, timeout=15)
        sock.settimeout(15)
        ok_ka = True
        for i in range(2):
            sock.sendall(
                f"GET /?n={i} HTTP/1.1\r\nHost: {args.domain}\r\n\r\n".encode())
            head, headers, rest = read_head(sock)
            status = int(head.split(b" ")[1])
            body = read_body(sock, headers, rest)
            if status != 200 or body != b"hello-from-main-target":
                ok_ka = False
                checks.fail(f"Keep-Alive 第 {i} 个请求", f"status={status} body={body!r}")
                break
        stop_socket(sock)
        if ok_ka:
            checks.ok("Keep-Alive 同一连接两个请求", "两次均 200，连接复用")

        # 9) WebSocket
        websocket_echo(checks, http_addr, args.domain)

        # 10) Connection: close
        sock, status, headers, body = request(http_addr, args.domain, path="/close")
        extra = sock.recv(16)
        stop_socket(sock)
        checks.check(status == 200 and body == b"bye\n" and extra == b"",
                     "Connection: close 后服务端关闭连接",
                     f"status={status} extra={extra!r}")

        # 11) 未匹配域名 404
        status, headers, _ = curl(checks, http_addr, "nope.local", "未匹配域名 404")
        checks.check(status == 404 and headers.get("connection", "").lower() == "close",
                     "未匹配域名 -> 404 + Connection: close", f"status={status}")

        # 12) npc 离线 -> 502
        npc.terminate()
        try:
            npc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            npc.kill()
        npc = None
        time.sleep(1.0)

        def offline_502():
            try:
                sock, status, _, _ = request(http_addr, args.domain, timeout=5)
                stop_socket(sock)
                return status == 502
            except Exception:  # noqa: BLE001
                return False

        ok, err = wait_until(offline_502, args.timeout)
        checks.check(ok, "npc 离线 -> 502", f"last={err}" if not ok else "")

    except Exception:  # noqa: BLE001
        print("UNEXPECTED ERROR:", file=sys.stderr)
        traceback.print_exc()
        checks.fail("脚本异常", "见上方 traceback")
    finally:
        if npc is not None and npc.poll() is None:
            npc.terminate()
            try:
                npc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                npc.kill()
        stop_file.write_text("stop", encoding="utf-8")
        try:
            harness.wait(timeout=30)
        except subprocess.TimeoutExpired:
            harness.kill()
        harness_log.close()
        if npc_log:
            npc_log.close()
        main_target.shutdown()
        api_target.shutdown()

    passed = len(checks.items) - len(checks.failed)
    print()
    print(f"RESULT {passed}/{len(checks.items)} passed, {len(checks.failed)} failed")
    print(f"logs: {run_dir}")
    return 0 if not checks.failed else 1


def secrets_token() -> str:
    import secrets
    return secrets.token_urlsafe(24)


def parse_addr(text: str):
    host, port = text.rsplit(":", 1)
    return host, int(port)


def tail(path: Path, limit=4096) -> str:
    try:
        data = path.read_bytes()
        return data[-limit:].decode("utf-8", "replace")
    except OSError as exc:
        return f"<cannot read {path}: {exc}>"


if __name__ == "__main__":
    sys.exit(main())
