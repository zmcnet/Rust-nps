//! 更新源客户端与二进制校验：版本比较、清单读取、sha256 校验、更新计划与安全替换。
//!
//! 本模块只负责「读清单 → 比版本 → 校验 → 备份替换」，不碰 CLI、实例管理与进程控制；
//! 调用方（`commands::cmd_update`）负责提供更新源、当前版本与目标 exe 路径，
//! 并在 [`apply`] 的 `before_replace` 回调里停掉正在运行的实例。
//!
//! # 为什么没有 HTTP 更新源
//!
//! 本项目坚持零额外依赖，不引入 `reqwest` / `ureq` / `hyper` 之类的 HTTP 客户端。
//! 手写 HTTP(S) 客户端风险高（TLS 证书链校验、重定向策略、超时、分块传输），
//! 属于独立工作，因此本模块 **只接受本地目录**：调用方应先把二进制下载到目录，
//! 再把目录路径传进来。传入 `http(s)://...` 时，[`plan`] 会给出明确错误。
//!
//! # 签名验证（未实现）
//!
//! [`Manifest`] 目前只有 sha256，只能发现传输/落盘损坏，不能证明清单本身可信。
//! 真正的防篡改需要签名（例如对清单 + 二进制做 ed25519/rsa 验签，并内置公钥），
//! 属后续工作；[`Manifest`] 允许出现未知字段，以便后续平滑加入 `signature` 字段。

use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Component, Path, PathBuf};

use anyhow::{bail, Context, Result};

/// 清单文件名（相对更新源目录）。
pub const MANIFEST_FILE: &str = "manifest.json";

/// 备份后缀：`rnpc.exe` → `rnpc.exe.bak`。
pub const BACKUP_SUFFIX: &str = ".bak";

/// 读文件时的块大小（64 KiB）。
const READ_CHUNK: usize = 64 * 1024;

// ---------------------------------------------------------------------------
// 清单
// ---------------------------------------------------------------------------

/// 更新清单（`manifest.json`）。
///
/// 必需字段只是 `version` 与 `binary`；未知字段会被忽略，便于后续加入 `signature`。
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct Manifest {
    /// 目标版本，形如 `1.2.3` / `1.2.3-beta.1`
    pub version: String,
    /// 二进制相对路径（相对清单所在目录）
    pub binary: String,
    /// 可选 sha256（hex，大小写均可）
    pub sha256: Option<String>,
    /// 最低支持的旧版本（低于此版本要求手动升级）；可选
    pub min_version: Option<String>,
}

// ---------------------------------------------------------------------------
// 版本比较
// ---------------------------------------------------------------------------

/// 版本比较结果：`Older` / `Same` / `Newer` 描述**左值相对右值**的关系。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionOrder {
    /// 左值更低
    Older,
    /// 相等
    Same,
    /// 左值更高
    Newer,
}

/// 预发布段的一个标识符：数字段按数值比较，字母段按 ASCII 比较。
#[derive(Debug, Clone, PartialEq, Eq)]
enum PreId {
    Num(u64),
    Alpha(String),
}

/// 解析后的版本号。
#[derive(Debug, Clone, PartialEq, Eq)]
struct Version {
    core: [u64; 3],
    pre: Option<Vec<PreId>>,
}

/// 解析 `主.次.修订[-预发布][+构建元数据]`。
///
/// - 缺失段补 0：`1.2` == `1.2.0`，`1` == `1.0.0`
/// - 最多三段，四段及以上视为非法
/// - `+构建元数据` 被忽略（按 semver，不参与优先级）
fn parse_version(raw: &str) -> Result<Version> {
    let text = raw.trim();
    if text.is_empty() {
        bail!("版本号为空");
    }

    // 先切构建元数据（`+`），再切预发布（`-`）：`1.2.3-beta+exp.sha.5114f85`
    let (head, build) = match text.split_once('+') {
        Some((head, build)) => (head, Some(build)),
        None => (text, None),
    };
    if let Some(build) = build {
        if build.is_empty() {
            bail!("版本号 {raw:?} 的构建元数据部分为空");
        }
    }

    let (core_text, pre_text) = match head.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (head, None),
    };

    let parts: Vec<&str> = core_text.split('.').collect();
    if parts.len() > 3 {
        bail!("版本号 {raw:?} 非法：只支持 `主.次.修订` 三段，实际 {} 段", parts.len());
    }
    if parts.is_empty() {
        bail!("版本号 {raw:?} 非法：缺少主版本号");
    }

    let mut core = [0u64; 3];
    for (i, part) in parts.iter().enumerate() {
        if part.is_empty() {
            bail!("版本号 {raw:?} 非法：存在空段");
        }
        if !part.bytes().all(|b| b.is_ascii_digit()) {
            bail!("版本号 {raw:?} 非法：段 {part:?} 不是十进制数字");
        }
        core[i] = part
            .parse::<u64>()
            .with_context(|| format!("版本号 {raw:?} 非法：段 {part:?} 超出 u64 范围"))?;
    }

    let pre = match pre_text {
        None => None,
        Some(pre) => {
            if pre.is_empty() {
                bail!("版本号 {raw:?} 非法：预发布后缀为空");
            }
            let mut ids = Vec::new();
            for id in pre.split('.') {
                if id.is_empty() {
                    bail!("版本号 {raw:?} 非法：预发布后缀含空标识符");
                }
                if id.bytes().all(|b| b.is_ascii_digit()) {
                    let value = id.parse::<u64>().with_context(|| {
                        format!("版本号 {raw:?} 非法：预发布数字段 {id:?} 超出 u64 范围")
                    })?;
                    ids.push(PreId::Num(value));
                } else {
                    ids.push(PreId::Alpha(id.to_owned()));
                }
            }
            Some(ids)
        }
    };

    Ok(Version { core, pre })
}

/// 比较两个版本字符串（`a` 相对 `b`）。
///
/// 语义与 semver 一致：
/// - `主.次.修订` 逐段数值比较，缺段补 0
/// - 有预发布后缀的版本**小于**同版本正式版（`1.0.0-beta < 1.0.0`）
/// - 预发布标识符：数字段 < 字母段，数字按数值、字母按 ASCII；前缀相同则短者小
/// - `+构建元数据` 不参与比较
///
/// 任一版本字符串非法（空、非数字段、段数 > 3、空预发布后缀等）**返回错误**，
/// 不会静默当成相等。
pub fn compare_versions(a: &str, b: &str) -> Result<VersionOrder> {
    let left = parse_version(a)?;
    let right = parse_version(b)?;
    Ok(match left.core.cmp(&right.core) {
        std::cmp::Ordering::Less => return Ok(VersionOrder::Older),
        std::cmp::Ordering::Greater => return Ok(VersionOrder::Newer),
        std::cmp::Ordering::Equal => match (&left.pre, &right.pre) {
            (None, None) => VersionOrder::Same,
            // 正式版高于同号预发布版
            (None, Some(_)) => VersionOrder::Newer,
            (Some(_), None) => VersionOrder::Older,
            (Some(l), Some(r)) => compare_pre(l, r),
        },
    })
}

fn compare_pre(left: &[PreId], right: &[PreId]) -> VersionOrder {
    for (l, r) in left.iter().zip(right.iter()) {
        let ord = match (l, r) {
            (PreId::Num(l), PreId::Num(r)) => l.cmp(r),
            // 数字标识符优先级低于字母标识符
            (PreId::Num(_), PreId::Alpha(_)) => std::cmp::Ordering::Less,
            (PreId::Alpha(_), PreId::Num(_)) => std::cmp::Ordering::Greater,
            (PreId::Alpha(l), PreId::Alpha(r)) => l.as_bytes().cmp(r.as_bytes()),
        };
        match ord {
            std::cmp::Ordering::Less => return VersionOrder::Older,
            std::cmp::Ordering::Greater => return VersionOrder::Newer,
            std::cmp::Ordering::Equal => {}
        }
    }
    // 前缀相同：标识符更少的一侧更小（`1.0.0-beta < 1.0.0-beta.1`）
    match left.len().cmp(&right.len()) {
        std::cmp::Ordering::Less => VersionOrder::Older,
        std::cmp::Ordering::Greater => VersionOrder::Newer,
        std::cmp::Ordering::Equal => VersionOrder::Same,
    }
}

// ---------------------------------------------------------------------------
// SHA-256
// ---------------------------------------------------------------------------

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// 流式 SHA-256（纯 Rust，无依赖）。
struct Sha256 {
    state: [u32; 8],
    buf: [u8; 64],
    buf_len: usize,
    total_len: u64,
}

impl Sha256 {
    fn new() -> Self {
        Self {
            state: H0,
            buf: [0u8; 64],
            buf_len: 0,
            total_len: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total_len = self.total_len.wrapping_add(data.len() as u64);

        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }

        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.compress(&block);
            data = &data[64..];
        }

        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    fn finalize_hex(mut self) -> String {
        let bit_len = self.total_len.wrapping_mul(8);
        // 补 0x80，再补 0 到 56 (mod 64)，最后 8 字节大端位长
        self.update(&[0x80]);
        while self.buf_len != 56 {
            self.update(&[0x00]);
        }
        self.update(&bit_len.to_be_bytes());

        let mut out = String::with_capacity(64);
        for word in self.state {
            let _ = write!(out, "{word:08x}");
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[4 * i],
                block[4 * i + 1],
                block[4 * i + 2],
                block[4 * i + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }

        for (slot, value) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(value);
        }
    }
}

/// 计算文件 sha256（hex 小写，流式读取，不整文件入内存）。
pub fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path).with_context(|| format!("打开文件失败: {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; READ_CHUNK];
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("读取文件失败: {}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize_hex())
}

/// 校验文件 sha256（大小写不敏感、忽略两端空白）。
///
/// 期望值不是 64 位十六进制或与实际值不一致时**返回错误**（调用方必须拒绝更新）。
pub fn verify_sha256(path: &Path, expected: &str) -> Result<()> {
    let want = expected.trim().to_ascii_lowercase();
    if want.len() != 64 || !want.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!(
            "期望的 sha256 格式非法（需 64 位十六进制）: {:?}",
            expected.trim()
        );
    }
    let got = sha256_file(path)?;
    if got != want {
        bail!(
            "sha256 校验失败，拒绝更新: 期望 {want}，实际 {got}（文件 {}）",
            path.display()
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 清单读取与路径安全
// ---------------------------------------------------------------------------

/// 传入的是 URL 而不是本地目录时，给出统一的可读错误。
fn reject_url(dir: &Path) -> Result<()> {
    let text = dir.to_string_lossy();
    let trimmed = text.trim();
    let lower = trimmed.to_ascii_lowercase();
    let looks_like_url = lower.starts_with("http://")
        || lower.starts_with("https://")
        || trimmed.contains("://");
    if looks_like_url {
        bail!(
            "HTTP 更新源尚未支持；请使用本地目录或镜像下载后指向目录（收到 {trimmed:?}）。\
             HTTP 需要 TLS 证书校验与签名机制，属后续工作"
        );
    }
    Ok(())
}

/// 从本地目录读清单（`manifest.json`）。
///
/// 同时做字段级校验：版本号必须可解析、`binary` 非空、`sha256`（若给出）必须是
/// 64 位十六进制，避免把坏清单带到替换阶段。
pub fn read_manifest_dir(dir: &Path) -> Result<Manifest> {
    reject_url(dir)?;
    let path = dir.join(MANIFEST_FILE);
    let text = fs::read_to_string(&path).with_context(|| {
        format!(
            "读取更新清单失败: {}（更新源目录应包含 {MANIFEST_FILE}）",
            path.display()
        )
    })?;
    let manifest: Manifest = serde_json::from_str(&text).with_context(|| {
        format!(
            "解析更新清单失败: {}（需要字段 version、binary，可选 sha256、min_version）",
            path.display()
        )
    })?;

    if manifest.version.trim().is_empty() {
        bail!("更新清单 {} 的 version 为空", path.display());
    }
    parse_version(&manifest.version)
        .with_context(|| format!("更新清单 {} 的 version 非法", path.display()))?;
    if manifest.binary.trim().is_empty() {
        bail!("更新清单 {} 的 binary 为空", path.display());
    }
    if let Some(min) = &manifest.min_version {
        parse_version(min)
            .with_context(|| format!("更新清单 {} 的 min_version 非法", path.display()))?;
    }
    if let Some(sum) = &manifest.sha256 {
        let sum = sum.trim();
        if sum.len() != 64 || !sum.bytes().all(|b| b.is_ascii_hexdigit()) {
            bail!(
                "更新清单 {} 的 sha256 格式非法（需 64 位十六进制）: {sum:?}",
                path.display()
            );
        }
    }
    Ok(manifest)
}

/// 校验清单里的 `binary` 是安全相对路径，并返回该相对路径。
///
/// 拒绝绝对路径（含 Windows 盘符/UNC）与任何 `..` 段。
fn safe_binary_rel(rel: &str) -> Result<&Path> {
    let rel = rel.trim();
    if rel.is_empty() {
        bail!("更新清单字段 binary 为空");
    }
    for comp in Path::new(rel).components() {
        match comp {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir => {
                bail!("更新清单 binary 含上级目录 `..`，拒绝以防目录穿越: {rel}")
            }
            Component::RootDir | Component::Prefix(_) => {
                bail!("更新清单 binary 必须是相对路径，拒绝绝对路径: {rel}")
            }
        }
    }
    Ok(Path::new(rel))
}

/// 把清单里的相对 `binary` 解析成更新源目录内的真实路径。
///
/// 先用 [`safe_binary_rel`] 拒绝绝对路径与 `..`，再在 canonicalize 后确认
/// 仍落在目录内（防符号链接逃逸），最后要求文件真实存在。
fn resolve_binary(dir: &Path, rel: &str) -> Result<PathBuf> {
    let raw = safe_binary_rel(rel)?;
    let canon_dir = dir
        .canonicalize()
        .with_context(|| format!("更新源目录无效: {}", dir.display()))?;
    let joined = canon_dir.join(raw);
    let canon = joined
        .canonicalize()
        .with_context(|| format!("更新源缺少二进制文件: {}", joined.display()))?;
    if !canon.starts_with(&canon_dir) {
        bail!("更新清单 binary 指向更新源目录之外，拒绝: {rel}");
    }
    if !canon.is_file() {
        bail!("更新源 binary 不是普通文件: {}", canon.display());
    }
    Ok(canon)
}

// ---------------------------------------------------------------------------
// 计划
// ---------------------------------------------------------------------------

/// 更新计划：只描述将要发生什么，不做任何文件修改。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// 当前版本（调用方传入）
    pub current: String,
    /// 清单里的目标版本
    pub target: String,
    /// `current` 相对 `target` 的版本关系：`Older` 表示当前版本更旧（有更新可用），
    /// `Newer` 表示当前版本比清单更新（清单是降级），`Same` 表示已是最新。
    ///
    /// 注意方向：这是 **current 相对 target**，不是 target 相对 current。
    pub order: VersionOrder,
    /// 清单指向的二进制是否真实存在
    pub binary_present: bool,
    /// 需要执行的 sha256 校验（清单给出时）
    pub checksum: Option<String>,
    /// 拒绝更新的原因（版本过低等）
    pub blocked: Option<String>,
}

/// 制定更新计划。
///
/// 不做任何修改。`Plan::order` 是 **当前版本相对清单版本**的关系：
/// `Older` = 当前更旧（有更新可用）、`Newer` = 当前更新（清单是降级）、
/// `Same` = 已是最新。
///
/// 以下情况返回错误（而不是静默"无需更新"）：
/// - `dir` 是 URL（HTTP 更新源尚未支持）
/// - 更新源目录或 `manifest.json` 缺失/损坏
/// - 版本号非法，或 `binary` 是绝对路径/含 `..`
pub fn plan(dir: &Path, current_version: &str) -> Result<Plan> {
    reject_url(dir)?;
    if !dir.is_dir() {
        bail!("更新源目录不存在或不是目录: {}", dir.display());
    }
    let manifest = read_manifest_dir(dir)?;
    let order = compare_versions(current_version, &manifest.version).with_context(|| {
        format!(
            "版本比较失败: current={current_version:?}, target={:?}",
            manifest.version
        )
    })?;
    // 先做路径安全校验（拒绝 `..` 与绝对路径）；文件缺失只记录，不在计划阶段失败。
    let rel = safe_binary_rel(&manifest.binary)?;
    let binary_present = dir.join(rel).is_file();

    let blocked = match &manifest.min_version {
        Some(min) => match compare_versions(current_version, min).with_context(|| {
            format!("min_version 比较失败: current={current_version:?}, min_version={min:?}")
        })? {
            VersionOrder::Older => Some(format!(
                "当前版本 {current_version} 低于最低支持版本 {min}，需手动升级"
            )),
            _ => None,
        },
        None => None,
    };

    Ok(Plan {
        current: current_version.to_owned(),
        target: manifest.version,
        order,
        binary_present,
        checksum: manifest.sha256,
        blocked,
    })
}

// ---------------------------------------------------------------------------
// 执行
// ---------------------------------------------------------------------------

/// 备份路径：在原路径后追加 `.bak`（`rnpc.exe` → `rnpc.exe.bak`）。
pub fn backup_path(dest_exe: &Path) -> PathBuf {
    let mut raw = dest_exe.as_os_str().to_owned();
    raw.push(BACKUP_SUFFIX);
    PathBuf::from(raw)
}

/// 尽力去掉只读属性（还原时需要，失败忽略）。
fn make_writable(path: &Path) {
    if !path.exists() {
        return;
    }
    if let Ok(meta) = fs::metadata(path) {
        let mut perms = meta.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        let _ = fs::set_permissions(path, perms);
    }
}

/// 执行更新：校验 → 备份 → 替换 → 落盘复校 → 失败还原。
///
/// `before_replace` 在替换前调用（用于停实例）；它失败则**不替换**，直接把错误返回。
/// 返回备份路径（旧文件存在时该路径指向旧内容；旧文件不存在时该路径不存在）。
///
/// # 失败语义
///
/// - 替换前失败（校验、备份、回调）：目标文件保持原样
/// - 替换后失败：从备份还原，错误信息注明「已还原」
/// - 还原也失败：错误信息注明「可能已损坏，请手动恢复 <备份路径>」
pub fn apply(
    dir: &Path,
    plan: &Plan,
    dest_exe: &Path,
    before_replace: impl FnOnce() -> Result<()>,
) -> Result<PathBuf> {
    reject_url(dir)?;
    if let Some(reason) = &plan.blocked {
        bail!("拒绝更新：{reason}");
    }
    if plan.order == VersionOrder::Same {
        bail!(
            "当前版本 {} 已是清单目标版本，无需更新",
            plan.current
        );
    }

    // 计划与执行之间清单可能被替换：重新读一次并核对，避免"计划的数据、执行的文件"。
    let manifest = read_manifest_dir(dir)?;
    if manifest.version.trim() != plan.target.trim() {
        bail!(
            "更新源在制定计划后发生变化：计划目标 {}，当前清单 {}；请重新检查更新",
            plan.target,
            manifest.version
        );
    }
    let source = resolve_binary(dir, &manifest.binary)?;
    match (manifest.sha256.as_deref(), plan.checksum.as_deref()) {
        (Some(a), Some(b)) if a.trim().eq_ignore_ascii_case(b.trim()) => {}
        (None, None) => {}
        _ => bail!("更新源在制定计划后发生变化：清单 sha256 与计划不一致；请重新检查更新"),
    }

    // 1) 校验（失败则不进入任何文件修改）
    if let Some(expected) = &manifest.sha256 {
        verify_sha256(&source, expected)?;
    }

    // 2) 目标路径预检（放在停实例之前，避免无谓停服）
    let Some(parent) = dest_exe.parent() else {
        bail!("目标路径无效（没有父目录）: {}", dest_exe.display());
    };
    if !parent.is_dir() {
        bail!("目标目录不存在: {}", parent.display());
    }
    if dest_exe.is_dir() {
        bail!("目标路径是目录而不是文件: {}", dest_exe.display());
    }

    // 3) 停实例：失败则不替换
    before_replace()?;

    // 4) 备份 → 替换 → 落盘复校
    let backup = backup_path(dest_exe);
    let had_old = dest_exe.is_file();
    if had_old {
        fs::copy(dest_exe, &backup)
            .with_context(|| format!("备份旧二进制失败: {}", backup.display()))?;
    }

    let replaced = (|| -> Result<()> {
        fs::copy(&source, dest_exe)
            .with_context(|| format!("替换二进制失败: {}", dest_exe.display()))?;
        // 落盘复校：确认写下去的就是源文件
        let src_sum = sha256_file(&source)?;
        let dst_sum = sha256_file(dest_exe)?;
        if src_sum != dst_sum {
            bail!(
                "替换后校验失败: 落盘 sha256 {dst_sum} 与源 {src_sum} 不一致（{}）",
                dest_exe.display()
            );
        }
        Ok(())
    })();

    match replaced {
        Ok(()) => Ok(backup),
        Err(err) => match rollback(dest_exe, &backup, had_old) {
            Ok(()) if had_old => bail!(
                "{err:#}\n更新失败，已还原原二进制（备份: {}）",
                backup.display()
            ),
            Ok(()) => bail!("{err:#}\n更新失败，已删除未完成的写入（目标原先不存在）"),
            Err(rb) => bail!(
                "{err:#}\n更新失败，且还原失败（{rb:#}）：{} 可能已损坏，请手动恢复 {}",
                dest_exe.display(),
                backup.display()
            ),
        },
    }
}

/// 还原：有备份则写回，无备份则删除半成品。
fn rollback(dest_exe: &Path, backup: &Path, had_old: bool) -> Result<()> {
    if had_old {
        make_writable(dest_exe);
        fs::copy(backup, dest_exe)
            .with_context(|| format!("从备份还原失败: {}", backup.display()))?;
    } else if dest_exe.exists() {
        make_writable(dest_exe);
        fs::remove_file(dest_exe)
            .with_context(|| format!("删除未完成的写入失败: {}", dest_exe.display()))?;
    }
    Ok(())
}
