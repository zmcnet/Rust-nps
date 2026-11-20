#!/usr/bin/env bash
# rnps Linux 安装脚本（systemd 发行版）
#
# 用法（root）：
#   ./install.sh                 # 使用脚本同目录下的 rnps，或 PATH 中的 rnps
#   ./install.sh /path/to/rnps   # 指定二进制
#
# 做的事：
#   1. 创建系统用户 nps（无登录 shell）
#   2. 安装二进制到 /usr/local/bin/rnps
#   3. 创建 /etc/nps，放配置与 0600 的环境文件
#   4. 首次安装时生成随机管理令牌；已有非空令牌则原样保留
#   5. 安装并启用 systemd 单元
#
# 不会覆盖已有的 /etc/nps/nps.env（非空令牌）和 /etc/nps/nps.json。
# 卸载步骤见 README.md。

set -euo pipefail

# Debian/Ubuntu 上 useradd/groupadd 位于 /usr/sbin，而普通用户或 sudo 的
# secure_path 未必包含它。显式补进 PATH，避免"命令找不到"。
PATH="/usr/local/sbin:/usr/sbin:/sbin:${PATH}"

BINARY_SRC="${1:-}"
BIN_DEST="/usr/local/bin/rnps"
CONF_DIR="/etc/nps"
ENV_FILE="${CONF_DIR}/nps.env"
CONF_FILE="${CONF_DIR}/nps.json"
UNIT_FILE="/etc/systemd/system/rnps.service"
SERVICE_NAME="rnps.service"
RUN_USER="nps"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

log() { printf '%s\n' "==> $*"; }
die() { printf '错误: %s\n' "$*" >&2; exit 1; }

# 临时令牌文件可能含密钥：任何退出路径都删除它
TMP_ENV=""
cleanup() {
    if [ -n "$TMP_ENV" ]; then
        rm -f -- "$TMP_ENV"
    fi
}
trap cleanup EXIT INT TERM

# ---------------------------------------------------------------- 前置检查
[ "$(id -u)" -eq 0 ] || die "请用 root 运行（sudo ./install.sh）"
command -v systemctl >/dev/null 2>&1 || die "未找到 systemctl；本脚本仅支持 systemd 发行版"

if [ -z "$BINARY_SRC" ]; then
    if [ -x "${SCRIPT_DIR}/rnps" ]; then
        BINARY_SRC="${SCRIPT_DIR}/rnps"
    elif command -v rnps >/dev/null 2>&1; then
        BINARY_SRC=$(command -v rnps)
    else
        die "未找到 rnps 二进制；请执行 ./install.sh /path/to/rnps"
    fi
fi
[ -f "$BINARY_SRC" ] || die "二进制不存在: $BINARY_SRC"

# 防止误装 Windows 构建产物
if command -v file >/dev/null 2>&1; then
    if ! file -b "$BINARY_SRC" | grep -qi 'ELF'; then
        die "$BINARY_SRC 不是 Linux ELF 可执行文件"
    fi
fi

# 提前验证二进制能在本机运行（架构不匹配 / 缺动态库会在这里暴露）
if ! "$BINARY_SRC" --version >/dev/null 2>&1; then
    die "$BINARY_SRC 无法在本机运行（架构不匹配或缺少动态库）"
fi

# ---------------------------------------------------------------- 用户
# systemd 单元里写的是 User=nps / Group=nps，所以组必须存在。
# 部分发行版的 useradd 不会自动建同名组，这里显式处理。
for tool in groupadd useradd; do
    command -v "$tool" >/dev/null 2>&1 || die "缺少 ${tool}（请安装 shadow/passwd 工具集）"
done

if ! grep -q "^${RUN_USER}:" /etc/group 2>/dev/null; then
    log "创建系统组 ${RUN_USER}"
    groupadd --system "$RUN_USER"
fi

if ! id -u "$RUN_USER" >/dev/null 2>&1; then
    log "创建系统用户 ${RUN_USER}"
    nologin=/usr/sbin/nologin
    [ -x "$nologin" ] || nologin=/bin/false
    useradd --system --no-create-home --gid "$RUN_USER" --shell "$nologin" "$RUN_USER"
else
    log "用户 ${RUN_USER} 已存在，沿用"
fi

# ---------------------------------------------------------------- 二进制
log "安装二进制到 ${BIN_DEST}"
install -o root -g root -m 0755 "$BINARY_SRC" "$BIN_DEST"

# ---------------------------------------------------------------- 配置目录
install -d -o root -g root -m 0755 "$CONF_DIR"

if [ ! -f "$CONF_FILE" ]; then
    log "生成默认配置 ${CONF_FILE}（clients / tunnels 为空，需手工补充）"
    install -o root -g "$RUN_USER" -m 0640 "${SCRIPT_DIR}/nps.json.example" "$CONF_FILE"
else
    log "${CONF_FILE} 已存在，保留不覆盖"
    # 修正权限：配置里有 vkey，只给 root 和运行用户读
    chown root:"$RUN_USER" "$CONF_FILE"
    chmod 0640 "$CONF_FILE"
fi

# ---------------------------------------------------------------- 管理令牌
# 只在首次生成；已存在且非空则保留。不把令牌回显到标准输出，
# 避免留在安装日志/终端回滚里。
if [ ! -f "$ENV_FILE" ]; then
    install -o root -g root -m 0600 /dev/null "$ENV_FILE"
else
    # 令牌文件必须只有 root 能读
    chown root:root "$ENV_FILE"
    chmod 0600 "$ENV_FILE"
fi

existing_token=""
token_line=$(grep -m 1 '^NPS_ADMIN_TOKEN=' "$ENV_FILE" 2>/dev/null || true)
existing_token=${token_line#NPS_ADMIN_TOKEN=}

if [ -z "$existing_token" ]; then
    log "生成随机管理令牌（32 字节）"
    token=""
    if command -v openssl >/dev/null 2>&1; then
        token=$(openssl rand -base64 32 | tr -d '\n')
    elif [ -r /dev/urandom ]; then
        # 兜底：/dev/urandom + base64（coreutils 与 busybox 均可）
        token=$(head -c 32 /dev/urandom | base64 | tr -d '\n')
    fi
    [ -n "$token" ] || die "无法生成随机令牌（缺少 openssl 与 /dev/urandom）"
    [ "${#token}" -ge 24 ] || die "生成的令牌长度不足 24 字节"

    tmp_env=$(mktemp)
    TMP_ENV="$tmp_env"
    chmod 0600 "$tmp_env"
    {
        printf '# 由 install.sh 生成；权限必须为 0600。\n'
        printf 'NPS_ADMIN_TOKEN=%s\n' "$token"
        printf 'RUST_LOG=info\n'
    } >"$tmp_env"
    chown root:root "$tmp_env"
    install -o root -g root -m 0600 "$tmp_env" "$ENV_FILE"
    rm -f "$tmp_env"
    TMP_ENV=""
    unset token
    log "令牌已写入 ${ENV_FILE}（0600）。请立即备份到密码管理器："
    log "    sudo grep '^NPS_ADMIN_TOKEN=' ${ENV_FILE}"
else
    log "${ENV_FILE} 已有管理令牌，保留不变"
fi

# ---------------------------------------------------------------- systemd
log "安装 systemd 单元 ${UNIT_FILE}"
install -o root -g root -m 0644 "${SCRIPT_DIR}/rnps.service" "$UNIT_FILE"

systemctl daemon-reload
# enable --now 覆盖首次安装；随后的 restart 让升级场景也换上新二进制
systemctl enable --now "$SERVICE_NAME" >/dev/null
systemctl restart "$SERVICE_NAME"

# 给服务一点启动时间；失败时打印日志尾部
started=0
for (( attempt = 0; attempt < 10; attempt++ )); do
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        started=1
        break
    fi
    sleep 1
done
if [ "$started" -ne 1 ]; then
    printf '服务未能启动，最近日志：\n' >&2
    journalctl -u "$SERVICE_NAME" -n 30 --no-pager >&2 || true
    exit 1
fi

cat <<EOF

安装完成。

  配置文件    ${CONF_FILE}
  环境文件    ${ENV_FILE}（0600，含 NPS_ADMIN_TOKEN）
  systemd     ${UNIT_FILE}

下一步：
  1. 编辑 ${CONF_FILE}，按 packaging/README.md 加入 clients 与 tunnels
  2. systemctl restart ${SERVICE_NAME}
  3. 本机验证：
     TOKEN=\$(sudo grep '^NPS_ADMIN_TOKEN=' ${ENV_FILE} | cut -d= -f2-)
     curl -s -H "Authorization: Bearer \$TOKEN" http://127.0.0.1:8080/api/status

安全提醒：
  - 管理端是明文 HTTP；远程访问请套 HTTPS 反向代理或走 SSH 隧道
  - 当前只支持 TCP 隧道
  - 状态（启停/流量/连接计数）只在内存，重启后按配置恢复
EOF