# rnps 多阶段构建
#
# ⚠️ 未在本机验证（本机没有 Docker）。镜像标签与构建步骤按官方镜像与
#    Cargo 常规行为编写，首次真正构建时请核对构建日志。
#
# 构建（在 rust/ 目录下执行，构建上下文 = rust/ 工作区根）：
#   docker build -f packaging/Dockerfile -t rnps:local .
#
# 运行：
#   docker run -d --name rnps \
#     -e NPS_ADMIN_TOKEN="$(openssl rand -base64 32)" \
#     -p 8024:8024 -p 8080:8080 \
#     -v /etc/nps/nps.json:/etc/nps/nps.json:ro \
#     rnps:local
#
# 注意：
# - 只支持 TCP 隧道；UDP/HTTP 域名代理/SOCKS5/KCP/P2P/文件服务均未实现。
# - 管理端是明文 HTTP，容器化后依然需要自己套 HTTPS 反向代理。
# - NPS_ADMIN_TOKEN 必须显式传入（至少 24 字节），镜像不提供任何默认值。
# - 容器内默认读 /etc/nps/nps.json；配置里的监听地址若要被宿主机访问，
#   必须写成 0.0.0.0（默认 127.0.0.1 只在容器内可达）。

# ---------- 构建阶段 ----------
FROM rust:1.100-slim AS builder

WORKDIR /build

# 只复制清单与源码，避免把 target/、.git 等带进构建层
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates

# 内嵌网页资源由 nps-web 编入二进制，不需要 Node 或独立静态目录。
# release profile 已在 Cargo.toml 中设置 strip = true，无需额外 strip。
RUN cargo build --release --locked -p nps-app --bin rnps

# ---------- 运行阶段 ----------
FROM debian:bookworm-slim

# 只装最小证书集（供将来外连/健康检查使用），不装编译工具与 shell 调试工具
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# 非 root 运行；固定 uid/gid，便于挂载文件的权限规划
RUN groupadd --gid 10001 nps \
 && useradd --uid 10001 --gid nps --no-create-home --shell /usr/sbin/nologin nps

COPY --from=builder /build/target/release/rnps /usr/local/bin/rnps

# 构建期冒烟检查：确认二进制能在 bookworm 的 glibc 上运行。
# `--version` 不读取配置、不需要管理令牌，纯检查动态链接是否兼容。
# 若基础镜像的 glibc 比运行镜像新，这里会直接失败，而不是等到线上才崩。
# 真出现 GLIBC 不匹配时，改用与运行镜像同代的构建镜像（如
# `rust:1.100-slim-bookworm`）或改用 musl 目标静态链接。
RUN /usr/local/bin/rnps --version

# 配置目录只放"示例"，镜像内不包含任何密钥
RUN mkdir -p /etc/nps && chown root:root /etc/nps && chmod 0755 /etc/nps
COPY packaging/nps.json.example /etc/nps/nps.json.example

USER 10001:10001
WORKDIR /etc/nps

# 桥端口 + 管理端口（默认仅回环；要在容器外访问需改配置为 0.0.0.0）
EXPOSE 8024 8080

ENV RUST_LOG=info

ENTRYPOINT ["/usr/local/bin/rnps"]
CMD ["--config", "/etc/nps/nps.json"]