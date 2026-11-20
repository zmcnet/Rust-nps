#!/usr/bin/env python3
"""验证 file 模式（mode=file 文件服务）与真实原版 npc 互通。

原版拓扑（Go `client/local.go:startLocalFileServer` + `client/control.go`）：
  1. npc 用 `-config=npc.conf` 启动，先拨 WORK_CONFIG（conf 通道）做配置注册：
     每个 `[file]` 段作为一条 Task（mode=file）经 NEW_TASK 发给服务端；
  2. npc 对每个 file 任务拨独立的 WORK_FILE 连接，并在其上建 mux 会话，
     然后 `http.Server{Handler: StripPrefix(strip_pre, FileServer(Dir(local_path)))}.Serve(mux)`；
  3. 服务端在 server_port 监听 HTTP，把每条外部连接原样（裸字节、不发 Link 帧）
     经该 mux 的新子流转发给 npc —— 404 / 目录语义全部由 npc 侧 http.FileServer 决定
     （rust `file_service.rs`：服务端不解析 HTTP，local_path/strip_pre 仅展示）。

rnps 侧 tunnel 来源（两种并存，本测试用「静态配置 + conf 幂等复用」）：
  - rnps.json 的 `file_tunnels`（listen_addr 用与 npc server_port 相同的端口）；
  - npc NEW_TASK 注册（conf.rs register_file_task）：同 client+同名+同端口时幂等复用
    已监听的静态隧道，回 true 后 npc 才会启动本地文件服务。因此静态隧道 name 必须
    等于 npc.conf 的段名（display_name(remark)），conf_register 必须为 true。

覆盖检查：
  1 rnps 启动、两个 npc（两个客户端）经 -config 上线（管理 API 确认）
  2 根目录大文件（300 KiB）下载逐字节一致（sha256）
  3 子目录文件下载一致
  4 不存在路径返回 404（npc 侧 http.FileServer 语义，注明）
  5 strip_pre=/web/ 生效：/web/<name> 拿到文件；无前缀 /<name> 返回 404（Go StripPrefix 语义）
  6 npc 断开后请求失败（监听端口仍在但 file 通道已断），重启 npc 后恢复
  7 全程客户端 1 的文件服务不受客户端 2 断连/重启影响（per-client file 通道隔离）

Run:
    PYTHONIOENCODING=utf-8 python -I file-smoke.py --server-bin <rnps.exe> --npc-bin <npc.exe>

Exit codes:
    0  RESULT 全部 passed
    1  至少一项 FAIL（日志保留在 run dir）
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path

# tunables
BIG_SIZE = 300 * 1024         # 根目录大文件（要求 >= 256 KiB）
START_TIMEOUT = 40.0          # 服务端/客户端就绪上限
DOWNLOAD_TIMEOUT = 30.0       # 单次 HTTP 下载超时
DEAD_CLIENT_TIMEOUT = 25.0    # 断连后等到「请求失败」的上限
RECOVER_TIMEOUT = 60.0        # 重启 npc 后等到恢复的上限


class Fail(Exception):
    """硬性顺序错误（进程死了 / 端口没起来），直接终止后续检查。"""


PASS: list[str] = []
FAIL: list[str] = []


def ok(m: str) -> None:
    PASS.append(m)
    print(f"  PASS  {m}", flush=True)


def bad(m: str) -> None:
    FAIL.append(m)
    print(f"  FAIL  {m}", flush=True)


def free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tail(path: Path, limit: int = 5000) -> str:
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - limit))
            return redact(f.read().decode("utf-8", "replace"))
    except OSError as e:
        return f"<cannot read {path}: {e}>"


def log(msg: str) -> None:
    print(msg, flush=True)


def redact(text: str) -> str:
    """控制台输出前打码 vkey / token（覆盖 npc.conf、rnps.json 与 npc 日志）。

    npc 自己会在日志里打印 `web access login ... password:<vkey>`，因此
    `password:` 形式也要打码（本测试的 conf 里没有 password 配置项，不会误伤）。
    """
    text = re.sub(r"(vkey=)[0-9A-Za-z_\-]+", r"\1<redacted>", text)
    text = re.sub(r'("vkey"\s*:\s*")[^"]*(")', r"\1<redacted>\2", text)
    text = re.sub(r"(password:)[0-9A-Za-z_\-]+", r"\1<redacted>", text)
    return text


def spawn(name: str, argv: list[str], env: dict, log_path: Path, cwd: Path) -> dict:
    log(f"[run] {name}: " + " ".join(argv))
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


def stop(handle: dict | None, timeout: float = 8.0) -> None:
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
            f"{handle['name']} 提前退出 code={proc.returncode}:\n{tail(handle['log'])}"
        )


def http_get(url: str, timeout: float = DOWNLOAD_TIMEOUT) -> tuple[int, bytes]:
    """GET，返回 (status, body)。HTTP >=400 走 HTTPError（也有 body）。

    传输层失败（连接被关 / 超时 / 拒绝）向上抛异常，由调用方区分「期望成功」
    还是「期望失败」。
    """
    try:
        with urllib.request.urlopen(url, timeout=timeout) as rsp:
            return rsp.status, rsp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def try_fetch(url: str, timeout: float = 5.0) -> tuple[bool, str]:
    """「期望失败」探测：任何异常 / 非 200 都算失败（返回 True）。"""
    try:
        status, _ = http_get(url, timeout=timeout)
        return status != 200, f"status={status}"
    except Exception as e:  # noqa: BLE001 - 传输失败本身就是我们等的结果
        return True, f"{type(e).__name__}"


def wait_client_online(web_port: int, token: str, client_id: int, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:{web_port}/api/status",
                headers={"Authorization": f"Bearer {token}"},
            )
            with urllib.request.urlopen(req, timeout=3) as rsp:
                data = json.loads(rsp.read())
            for c in data.get("clients", []):
                if c.get("id") == client_id and c.get("online"):
                    return
        except Exception:  # noqa: BLE001 - web 未就绪时重试
            pass
        time.sleep(0.3)
    raise Fail(f"管理 API 里客户端 {client_id} 在 {timeout:.0f}s 内未上线")


def wait_file_ok(url: str, want: bytes, timeout: float, what: str) -> None:
    """轮询直到 GET 返回 200 且内容与 want 一致（file 通道就绪的探针）。"""
    deadline = time.monotonic() + timeout
    last = "not started"
    while time.monotonic() < deadline:
        try:
            status, body = http_get(url, timeout=10)
            if status == 200:
                if body == want:
                    return
                last = f"200 但内容不一致（收 {len(body)} 字节）"
            else:
                last = f"status={status}"
        except Exception as e:  # noqa: BLE001 - file 通道未就绪时重试
            last = f"{type(e).__name__}"
        time.sleep(0.4)
    raise Fail(f"{what} 在 {timeout:.0f}s 内未就绪（最后状态: {last}）")


def write_npc_conf(path: Path, bridge_port: int, vkey: str, server_port: int,
                   local_path: Path, strip_pre: str | None) -> None:
    lines = [
        "[common]",
        f"server_addr=127.0.0.1:{bridge_port}",
        "conn_type=tcp",
        f"vkey={vkey}",
        "auto_reconnection=true",
        "",
        "[file]",
        "mode=file",
        f"server_port={server_port}",
        f"local_path={local_path}",
    ]
    if strip_pre is not None:
        lines.append(f"strip_pre={strip_pre}")
    # 统一 LF：Go splitStr 在 Windows 上按 \r\n 切，LF-only 走 \n 分支，两者均可
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------
def run(args: argparse.Namespace) -> int:
    npc_bin = Path(args.npc_bin)
    server_bin = Path(args.server_bin)
    if not npc_bin.is_file():
        raise Fail(f"npc binary not found: {npc_bin}")
    if not server_bin.is_file():
        raise Fail(f"server binary not found: {server_bin}")

    run_dir = Path(tempfile.mkdtemp(prefix="nps-file-smoke-"))
    server = npc1 = npc2 = None
    try:
        # ---- 目录与文件（避免路径里出现 "host"：npc 把含 host 的段当域名代理）----
        dir_a = run_dir / "www-root"      # 客户端 1：根目录服务（无 strip_pre）
        (dir_a / "docs").mkdir(parents=True)
        dir_b = run_dir / "www-web"       # 客户端 2：strip_pre=/web/
        dir_b.mkdir()

        big = os.urandom(BIG_SIZE)
        (dir_a / "big.bin").write_bytes(big)
        note = "nps-file-mode note ünïcode 中文\n".encode("utf-8")
        (dir_a / "docs" / "note.txt").write_bytes(note)
        page = b"page served under /web/ prefix\n" + os.urandom(64)
        (dir_b / "page.txt").write_bytes(page)

        # ---- 端口 / vkey ----
        bridge, web, p1, p2 = free_port(), free_port(), free_port(), free_port()
        vkey1 = "vk-" + secrets.token_hex(12)
        vkey2 = "vk-" + secrets.token_hex(12)

        # ---- rnps 配置：静态 file_tunnels 与 npc server_port 同端口 ----
        # name 必须等于 npc.conf 段名（display_name("file")=="file"），
        # 否则 NEW_TASK 幂等复用不命中 → 端口冲突 → npc 反复重连。
        cfg = {
            "bridge_addr": f"127.0.0.1:{bridge}",
            "web_addr": f"127.0.0.1:{web}",
            "clients": [
                {"id": 1, "name": "file-root", "vkey": vkey1},
                {"id": 2, "name": "file-web", "vkey": vkey2},
            ],
            "tunnels": [],
            "conf_register": True,
            "conf_listen_host": "127.0.0.1",
            "file_tunnels": [
                {
                    "id": 1, "name": "file", "client_id": 1,
                    "listen_addr": f"127.0.0.1:{p1}",
                    "enabled": True, "target_addr": "",
                    "local_path": str(dir_a), "strip_pre": "",
                },
                {
                    "id": 2, "name": "file", "client_id": 2,
                    "listen_addr": f"127.0.0.1:{p2}",
                    "enabled": True, "target_addr": "",
                    "local_path": str(dir_b), "strip_pre": "/web/",
                },
            ],
        }
        cfg_path = run_dir / "rnps.json"
        cfg_path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

        conf_a = run_dir / "npc-root.conf"
        conf_b = run_dir / "npc-web.conf"
        write_npc_conf(conf_a, bridge, vkey1, p1, dir_a, None)
        write_npc_conf(conf_b, bridge, vkey2, p2, dir_b, "/web/")

        log(f"[rnps.json]\n{redact(cfg_path.read_text(encoding='utf-8'))}")
        log(f"[npc-root.conf]\n{redact(conf_a.read_text(encoding='utf-8'))}")
        log(f"[npc-web.conf]\n{redact(conf_b.read_text(encoding='utf-8'))}")

        env = dict(os.environ)
        env.setdefault("NPS_ADMIN_TOKEN", "file-smoke-" + secrets.token_hex(16))
        env.setdefault("RUST_LOG", "info")

        server = spawn("rnps", [str(server_bin), "--config", str(cfg_path)],
                       env, run_dir / "rnps.log", run_dir)

        # 等桥端口就绪
        deadline = time.monotonic() + START_TIMEOUT
        ready = False
        while time.monotonic() < deadline:
            ensure_alive(server)
            try:
                with socket.create_connection(("127.0.0.1", bridge), timeout=1):
                    ready = True
                    break
            except OSError:
                time.sleep(0.2)
        if not ready:
            raise Fail("rnps 桥端口未就绪:" + tail(server["log"]))
        ok(f"rnps 启动，桥端口就绪 (bridge={bridge}, web={web}, file 端口 p1={p1} p2={p2})")

        # ---- 两个 npc，均为 -config 模式（[common]+[file] 段）----
        npc1 = spawn("npc-root", [str(npc_bin), f"-config={conf_a}", "-log=stdout", "-log_level=7"],
                     dict(os.environ), run_dir / "npc-root.log", run_dir)
        npc2 = spawn("npc-web", [str(npc_bin), f"-config={conf_b}", "-log=stdout", "-log_level=7"],
                     dict(os.environ), run_dir / "npc-web.log", run_dir)

        ensure_alive(npc1)
        ensure_alive(npc2)
        wait_client_online(web, env["NPS_ADMIN_TOKEN"], 1, START_TIMEOUT)
        wait_client_online(web, env["NPS_ADMIN_TOKEN"], 2, START_TIMEOUT)
        ok("npc -config 模式上线：客户端 1/2 在管理 API 中均在线（conf 注册 + NEW_TASK 幂等复用）")

        # ---- 2. 根目录大文件 ----
        url_big = f"http://127.0.0.1:{p1}/big.bin"
        wait_file_ok(url_big, big, START_TIMEOUT, "根目录 big.bin 首次可下载")
        ensure_alive(npc1)
        status, body = http_get(url_big)
        if status == 200 and body == big:
            ok(f"根目录文件下载逐字节一致（{BIG_SIZE} 字节, sha256={sha256(big)[:16]}…）")
        else:
            bad(f"根目录文件不一致: status={status}, 收 {len(body)}/{BIG_SIZE} 字节")

        # ---- 3. 子目录文件 ----
        status, body = http_get(f"http://127.0.0.1:{p1}/docs/note.txt")
        if status == 200 and body == note:
            ok("子目录文件 docs/note.txt 下载内容一致")
        else:
            bad(f"子目录文件异常: status={status}, 收 {len(body)}/{len(note)} 字节")

        # ---- 4. 不存在路径 -> 404 ----
        # 服务端是裸字节转发（file_service.rs「能力边界」：不解析 HTTP），
        # 404 由 npc 侧 http.FileServer 产生，与原版 nps 行为一致。
        status, body = http_get(f"http://127.0.0.1:{p1}/no-such-file.bin")
        if status == 404:
            ok(f"不存在路径返回 404（npc 侧 http.FileServer 语义，body={body[:32]!r}…）")
        else:
            bad(f"不存在路径期望 404，实际 status={status}")

        # ---- 5. strip_pre=/web/ ----
        url_page = f"http://127.0.0.1:{p2}/web/page.txt"
        wait_file_ok(url_page, page, START_TIMEOUT, "strip_pre=/web/ 下的 page.txt")
        ensure_alive(npc2)
        status, body = http_get(url_page)
        if status == 200 and body == page:
            ok("strip_pre=/web/ 生效：GET /web/page.txt 内容一致")
        else:
            bad(f"/web/page.txt 异常: status={status}, 收 {len(body)}/{len(page)} 字节")

        status, _ = http_get(f"http://127.0.0.1:{p2}/page.txt")
        if status == 404:
            ok("strip_pre 前缀缺失：GET /page.txt 返回 404（Go http.StripPrefix 语义）")
        else:
            bad(f"无前缀 /page.txt 期望 404，实际 status={status}")

        # ---- 6. npc 断开 -> 请求失败；重启 -> 恢复 ----
        stop(npc2)
        npc2 = None
        log("[run] npc-web 已终止，等待 p2 请求失败 …")
        deadline = time.monotonic() + DEAD_CLIENT_TIMEOUT
        failed, detail = False, ""
        while time.monotonic() < deadline:
            ensure_alive(server)
            failed, detail = try_fetch(url_page, timeout=5.0)
            if failed:
                break
            time.sleep(0.5)
        if failed:
            ok(f"npc 断开后 p2 请求失败（监听端口仍在但 file 通道已断，{detail}）")
        else:
            bad(f"npc 断开后 {DEAD_CLIENT_TIMEOUT:.0f}s 内请求仍成功")

        # 重启 npc（同一份 conf；NEW_TASK 走幂等复用，静态隧道一直在监听）
        npc2 = spawn("npc-web-restart", [str(npc_bin), f"-config={conf_b}", "-log=stdout", "-log_level=7"],
                     dict(os.environ), run_dir / "npc-web-restart.log", run_dir)
        ensure_alive(npc2)
        try:
            wait_client_online(web, env["NPS_ADMIN_TOKEN"], 2, START_TIMEOUT)
            wait_file_ok(url_page, page, RECOVER_TIMEOUT, "重启后的 /web/page.txt")
            status, body = http_get(url_page)
            if status == 200 and body == page:
                ok("重启 npc 后 p2 恢复：/web/page.txt 逐字节一致")
            else:
                bad(f"重启后内容不一致: status={status}")
        except Fail as e:
            bad(f"重启 npc 未恢复: {e}\n{tail(run_dir / 'npc-web-restart.log')}")

        # ---- 7. 客户端 1 全程不受影响（per-client file 通道隔离）----
        ensure_alive(npc1)
        status, body = http_get(url_big)
        if status == 200 and body == big:
            ok("客户端 2 断连/重启期间，客户端 1 的文件服务始终可用（file 通道按 client_id 隔离）")
        else:
            bad(f"客户端 1 受影响: status={status}")

        if npc1["proc"].poll() is not None:
            bad(f"npc-root 提前退出 code={npc1['proc'].returncode}")

    except Fail as e:
        bad(str(e))
    except Exception:  # noqa: BLE001 - 报告并整体失败
        traceback.print_exc()
        bad("测试框架异常（见 traceback）")
    finally:
        stop(npc2)
        stop(npc1)
        stop(server)
        for name in ("npc-root.log", "npc-web.log", "npc-web-restart.log", "rnps.log"):
            p = run_dir / name
            if p.is_file() and name.startswith("npc"):
                log(f"--- {name} tail ---")
                log(tail(p))
        if server:
            log("--- rnps.log tail ---")
            log(tail(server["log"]))
        log(f"[run dir] {run_dir}")

    log("")
    print(f"RESULT {len(PASS)} passed, {len(FAIL)} failed", flush=True)
    return 0 if not FAIL else 1


def main() -> int:
    ap = argparse.ArgumentParser(description="Real Go npc [file] mode <-> Rust file tunnel smoke test")
    ap.add_argument("--server-bin", required=True, help="rnps.exe path")
    ap.add_argument("--npc-bin", required=True, help="real Go npc.exe path")
    args = ap.parse_args()
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
