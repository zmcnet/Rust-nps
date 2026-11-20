//! 更新源客户端与二进制校验的集成测试。
//!
//! 覆盖：版本比较、sha256（标准向量 + 1 MiB 与 Python `hashlib` 交叉验证）、
//! 清单错误信息、目录穿越拒绝、更新计划、以及 `apply` 的成功/校验失败/回调失败/还原路径。
//!
//! 所有临时目录都在系统 temp 下按 pid + 纳秒唯一命名，并在 [`TempDir`] 的 `Drop`
//! 里清理（含去掉只读属性，防止 Windows 上 read-only 文件残留）。

use std::cell::Cell;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::anyhow;
use nps_client::update_feed::{
    apply, backup_path, compare_versions, plan as make_plan, read_manifest_dir, sha256_file,
    verify_sha256,
    VersionOrder, MANIFEST_FILE,
};

// ---------------------------------------------------------------------------
// 辅助
// ---------------------------------------------------------------------------

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "rnpc-uf-{}-{tag}-{nanos}-{n}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("创建临时目录失败");
        Self { path }
    }

    fn join(&self, rel: &str) -> PathBuf {
        self.path.join(rel)
    }

    /// 建一个子目录并返回路径。
    fn dir(&self, rel: &str) -> PathBuf {
        let path = self.join(rel);
        fs::create_dir_all(&path).expect("创建子目录失败");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        rm_rf(&self.path);
    }
}

fn rm_rf(path: &Path) {
    if !path.exists() {
        return;
    }
    if path.is_dir() {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                rm_rf(&entry.path());
            }
        }
        make_writable(path);
        let _ = fs::remove_dir_all(path);
        let _ = fs::remove_dir(path);
    } else {
        make_writable(path);
        let _ = fs::remove_file(path);
    }
}

fn make_writable(path: &Path) {
    if let Ok(meta) = fs::metadata(path) {
        let mut perms = meta.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        let _ = fs::set_permissions(path, perms);
    }
}

fn write_manifest(dir: &Path, json: &str) {
    fs::write(dir.join(MANIFEST_FILE), json).expect("写清单失败");
}

/// 把路径塞进 JSON 字符串字面量前转义反斜杠/引号（Windows 路径必须转义）。
fn json_escape(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}

fn sha_of(path: &Path) -> String {
    sha256_file(path).expect("计算 sha256 失败")
}

/// 与 Python 端 `gen_vectors` 完全一致的确定性字节流（xorshift64* + 截断）。
fn deterministic_bytes(n: usize) -> Vec<u8> {
    let mut s: u64 = 0x243F_6A88_85A3_08D3;
    let mut out = Vec::with_capacity(n + 8);
    while out.len() < n {
        s ^= s >> 12;
        s ^= s << 25;
        s ^= s >> 27;
        let v = s.wrapping_mul(0x2545_F491_4F6C_DD1D);
        out.extend_from_slice(&v.to_le_bytes());
    }
    out.truncate(n);
    out
}

/// 准备一个「清单 + 二进制 + 目标 exe」的标准场景。
struct Fixture {
    dir: TempDir,
    feed: PathBuf,
    dest: PathBuf,
    new_bytes: Vec<u8>,
    checksum: String,
}

impl Fixture {
    fn new(tag: &str, manifest_version: &str, manifest_sha: Option<String>) -> Self {
        let dir = TempDir::new(tag);
        let feed = dir.dir("feed");
        let bin = dir.dir("bin");
        let new_bytes = b"NEW BINARY v2 payload".to_vec();
        fs::write(feed.join("rnpc.exe"), &new_bytes).expect("写新二进制失败");
        let checksum = sha_of(&feed.join("rnpc.exe"));
        let sha_field = match manifest_sha {
            Some(raw) => format!(r#","sha256":"{raw}""#),
            None => String::new(),
        };
        write_manifest(
            &feed,
            &format!(
                r#"{{"version":"{manifest_version}","binary":"rnpc.exe"{sha_field}}}"#
            ),
        );
        let dest = bin.join("rnpc.exe");
        fs::write(&dest, b"OLD v1 content").expect("写旧二进制失败");
        Self {
            dir,
            feed,
            dest,
            new_bytes,
            checksum,
        }
    }

    fn feed(&self) -> &Path {
        &self.feed
    }

    fn dest(&self) -> &Path {
        &self.dest
    }

    fn old_bytes(&self) -> &'static [u8] {
        b"OLD v1 content"
    }

    fn temp(&self) -> &TempDir {
        &self.dir
    }
}

// ---------------------------------------------------------------------------
// 版本比较
// ---------------------------------------------------------------------------

#[test]
fn version_order_basics() {
    let same = VersionOrder::Same;
    let older = VersionOrder::Older;
    let newer = VersionOrder::Newer;

    assert_eq!(compare_versions("1.0.0", "1.0.1").unwrap(), older);
    assert_eq!(compare_versions("1.0.1", "1.0.0").unwrap(), newer);
    assert_eq!(compare_versions("1.0.0", "1.0.0").unwrap(), same);

    // 缺段补 0
    assert_eq!(compare_versions("1.2", "1.2.0").unwrap(), same);
    assert_eq!(compare_versions("1.2.0", "1.2").unwrap(), same);
    assert_eq!(compare_versions("1", "1.0.0").unwrap(), same);
    assert_eq!(compare_versions("1.2", "1.2.1").unwrap(), older);

    // 逐段数值比较，不能按字符串比
    assert_eq!(compare_versions("2.0.0", "1.99.99").unwrap(), newer);
    assert_eq!(compare_versions("1.99.99", "2.0.0").unwrap(), older);
    assert_eq!(compare_versions("1.10.0", "1.9.0").unwrap(), newer);

    // 两端空白容忍；构建元数据不参与比较
    assert_eq!(compare_versions(" 1.0.0 ", "1.0.0").unwrap(), same);
    assert_eq!(
        compare_versions("1.0.0+exp.sha.5114f85", "1.0.0+other").unwrap(),
        same
    );
}

#[test]
fn version_prerelease_ordering() {
    assert_eq!(
        compare_versions("1.0.0-beta", "1.0.0").unwrap(),
        VersionOrder::Older,
        "预发布版必须小于同号正式版"
    );
    assert_eq!(
        compare_versions("1.0.0", "1.0.0-beta").unwrap(),
        VersionOrder::Newer
    );
    assert_eq!(
        compare_versions("1.0.0-alpha", "1.0.0-beta").unwrap(),
        VersionOrder::Older
    );
    assert_eq!(
        compare_versions("1.0.0-beta", "1.0.0-beta.1").unwrap(),
        VersionOrder::Older
    );
    assert_eq!(
        compare_versions("1.0.0-beta.2", "1.0.0-beta.10").unwrap(),
        VersionOrder::Older,
        "数字标识符按数值比较"
    );
    assert_eq!(
        compare_versions("1.0.0-1", "1.0.0-beta").unwrap(),
        VersionOrder::Older,
        "数字标识符优先级低于字母标识符"
    );
    assert_eq!(
        compare_versions("1.0.1-beta", "1.0.0").unwrap(),
        VersionOrder::Newer,
        "主次修订更高时预发布后缀不能翻盘"
    );
    assert_eq!(
        compare_versions("1.0.0-beta+1", "1.0.0-beta+2").unwrap(),
        VersionOrder::Same
    );
}

#[test]
fn version_illegal_is_error_not_silently_equal() {
    let bad = [
        "",
        "   ",
        "abc",
        "v1.0.0",
        "1.0.0.0",
        "1..0",
        "1.0.",
        ".1.0",
        "1.0.x",
        "1.0.0-",
        "1.0.0-beta..1",
        "1.0.0+",
        "-1.0.0",
        "99999999999999999999.0.0",
    ];
    for case in bad {
        let err = compare_versions(case, "1.0.0")
            .expect_err(&format!("非法版本 {case:?} 应报错"));
        assert!(
            !err.to_string().is_empty(),
            "非法版本 {case:?} 的错误信息不应为空"
        );
        assert!(
            compare_versions("1.0.0", case).is_err(),
            "右值非法时 {case:?} 也应报错"
        );
    }
}

// ---------------------------------------------------------------------------
// sha256
// ---------------------------------------------------------------------------

#[test]
fn sha256_standard_vectors() {
    let tmp = TempDir::new("sha-vec");

    let empty = tmp.join("empty.bin");
    fs::write(&empty, b"").unwrap();
    assert_eq!(
        sha_of(&empty),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );

    let abc = tmp.join("abc.bin");
    fs::write(&abc, b"abc").unwrap();
    assert_eq!(
        sha_of(&abc),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    // 大写 + 两端空白都必须接受
    verify_sha256(
        &abc,
        "  BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD  ",
    )
    .expect("sha256 校验应大小写不敏感");

    // 长度不对 → 格式错误
    let err = verify_sha256(&abc, "deadbeef").unwrap_err().to_string();
    assert!(err.contains("格式非法"), "错误信息应说明格式: {err}");

    // 长度对但内容不对 → 校验失败
    let err = verify_sha256(&abc, &"0".repeat(64)).unwrap_err().to_string();
    assert!(err.contains("校验失败"), "错误信息应说明校验失败: {err}");
    assert!(err.contains("拒绝更新"), "校验失败必须拒绝更新: {err}");
}

#[test]
fn sha256_long_standard_vectors() {
    let tmp = TempDir::new("sha-long");

    // 448-bit 标准向量
    let v448 = tmp.join("v448.bin");
    fs::write(
        &v448,
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    )
    .unwrap();
    assert_eq!(
        sha_of(&v448),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );

    // 896-bit 标准向量
    let v896 = tmp.join("v896.bin");
    fs::write(&v896, b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu").unwrap();
    assert_eq!(
        sha_of(&v896),
        "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
    );

    // 1,000,000 个 'a'（多块 + 长度尾部）
    let million = tmp.join("million-a.bin");
    fs::write(&million, vec![b'a'; 1_000_000]).unwrap();
    assert_eq!(
        sha_of(&million),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

#[test]
fn sha256_padding_boundaries() {
    // 期望值由 Python hashlib 对同一确定性字节流算出
    let cases: &[(usize, &str)] = &[
        (1, "0a3aaee7ccfb1a64f6d7bcd46657c27cb1f4569ae9e7c03445bd6c6fd013109b"),
        (55, "6a07ac45c1e7e2459ac531cea8a3903aa9a06bf77a65c9846d1dd0f21ec7a8aa"),
        (56, "ebf0b8896af2bbd62e269e9bebce3ea4bbebf57a0b79f3b4314876b4ed059593"),
        (63, "b8a33844726c83f493048a80f02adfcfcb80b9d4221592d8670f2ead0eb750ca"),
        (64, "320ea9be8f3ed6808b554c7be41919d9536328521fdea2e2831dab75f1ab0ec7"),
        (65, "f6d9ed03493e555db99cb5f018258d4d9845ffb87793b44abee6c4d7afe5ef3c"),
        (111, "68d6e15ca9a9b692697a497f97c5069278f01279c7dc9edda65e15fdda8271e4"),
        (119, "86b6b76f31917a78f31c971e680a9099cbf69d4bea5e3bd4def76013a7b11752"),
        (120, "e7fc3bea051e113a3aa0385bfbc03f8271f5bc72efc179369abb873f547945fe"),
        (127, "cb8b8273f098571f1d4871aaa39ececb56367b34f4f99b01dbffffbeda33dfdc"),
        (128, "55c92acfa2fe1bec0005304d88932f6d4dac791c41b209d6b7401a4a1674bf49"),
        (129, "ebf8b4fd8a7605900626ba3227f1154d84ef1037130020d3ce82ff755b5d62a8"),
        (4096, "c0066c46d36c84c23b594fc5c26b80b0321b81cc891d195dfa788132df61f2ae"),
    ];
    let tmp = TempDir::new("sha-boundary");
    for (size, expected) in cases {
        let path = tmp.join(&format!("n{size}.bin"));
        fs::write(&path, deterministic_bytes(*size)).unwrap();
        assert_eq!(&sha_of(&path), expected, "{size} 字节的 sha256 不符");
    }
}

#[test]
fn sha256_one_mib_matches_python_hashlib() {
    let tmp = TempDir::new("sha-1mib");
    let data = deterministic_bytes(1024 * 1024);
    assert_eq!(data.len(), 1024 * 1024);
    let path = tmp.join("one-mib.bin");
    fs::write(&path, &data).unwrap();
    let digest = sha_of(&path);
    println!("1 MiB 确定性数据 sha256 = {digest}");
    assert_eq!(
        digest,
        "87a33f4c16260ea42ff7590a700e67c153f1a693a4aed652739bd0bb17e81ece"
    );

    // 跨多块 + 非 8 字节整数倍收尾
    let tail = tmp.join("two-mib-plus.bin");
    fs::write(&tail, deterministic_bytes(2 * 1024 * 1024 + 7)).unwrap();
    let digest = sha_of(&tail);
    println!("2 MiB + 7 字节 sha256 = {digest}");
    assert_eq!(
        digest,
        "1857be13ff18980cc5363a5117624a0518bdbb4ee89a674ee1a0447afb37c788"
    );
}

// ---------------------------------------------------------------------------
// 清单读取
// ---------------------------------------------------------------------------

#[test]
fn manifest_errors_are_readable() {
    let tmp = TempDir::new("manifest-err");
    let feed = tmp.dir("feed");

    // 缺文件
    let err = read_manifest_dir(&feed).unwrap_err().to_string();
    assert!(err.contains("读取更新清单失败"), "错误信息应可读: {err}");
    assert!(err.contains(MANIFEST_FILE), "错误信息应指出文件名: {err}");

    // 非法 JSON
    write_manifest(&feed, "{ not json");
    let err = read_manifest_dir(&feed).unwrap_err().to_string();
    assert!(err.contains("解析更新清单失败"), "错误信息应可读: {err}");

    // 缺 version
    write_manifest(&feed, r#"{"binary":"rnpc.exe"}"#);
    let err = read_manifest_dir(&feed).unwrap_err().to_string();
    assert!(err.contains("version"), "应指出缺 version: {err}");

    // 缺 binary
    write_manifest(&feed, r#"{"version":"1.0.0"}"#);
    let err = read_manifest_dir(&feed).unwrap_err().to_string();
    assert!(err.contains("binary"), "应指出缺 binary: {err}");

    // 版本非法
    write_manifest(&feed, r#"{"version":"v1.0.0","binary":"rnpc.exe"}"#);
    let err = read_manifest_dir(&feed).unwrap_err().to_string();
    assert!(err.contains("version 非法"), "应指出版本非法: {err}");

    // version 为空
    write_manifest(&feed, r#"{"version":"  ","binary":"rnpc.exe"}"#);
    let err = read_manifest_dir(&feed).unwrap_err().to_string();
    assert!(err.contains("version 为空"), "应指出 version 为空: {err}");

    // binary 为空
    write_manifest(&feed, r#"{"version":"1.0.0","binary":"  "}"#);
    let err = read_manifest_dir(&feed).unwrap_err().to_string();
    assert!(err.contains("binary 为空"), "应指出 binary 为空: {err}");

    // sha256 格式非法
    write_manifest(
        &feed,
        r#"{"version":"1.0.0","binary":"rnpc.exe","sha256":"zz"}"#,
    );
    let err = read_manifest_dir(&feed).unwrap_err().to_string();
    assert!(err.contains("sha256 格式非法"), "应指出 sha256 非法: {err}");

    // min_version 非法
    write_manifest(
        &feed,
        r#"{"version":"1.0.0","binary":"rnpc.exe","min_version":"x"}"#,
    );
    let err = read_manifest_dir(&feed).unwrap_err().to_string();
    assert!(err.contains("min_version 非法"), "应指出 min_version 非法: {err}");

    // 合法清单可读，未知字段被忽略
    write_manifest(
        &feed,
        r#"{"version":"1.0.0","binary":"rnpc.exe","unknown_future_field":true}"#,
    );
    let manifest = read_manifest_dir(&feed).expect("合法清单应能读取");
    assert_eq!(manifest.version, "1.0.0");
    assert_eq!(manifest.binary, "rnpc.exe");
    assert_eq!(manifest.sha256, None);
    assert_eq!(manifest.min_version, None);
}

#[test]
fn plan_rejects_path_traversal_and_absolute_binary() {
    let tmp = TempDir::new("traversal");
    let feed = tmp.dir("feed");

    let traversal = [
        "../evil.exe",
        "../../evil.exe",
        "sub/../../evil.exe",
        "sub/../evil.exe",
    ];
    for rel in traversal {
        write_manifest(
            &feed,
            &format!(
                r#"{{"version":"2.0.0","binary":"{}"}}"#,
                json_escape(rel)
            ),
        );
        let err = make_plan(&feed, "1.0.0")
            .expect_err(&format!("含 `..` 的 binary {rel:?} 必须被拒绝"))
            .to_string();
        assert!(err.contains("目录穿越"), "错误信息应说明原因: {err}");
    }

    let absolute: &[&str] = if cfg!(windows) {
        &[
            r"C:\Windows\System32\evil.exe",
            r"\\server\share\evil.exe",
            r"\evil.exe",
        ]
    } else {
        &["/etc/evil.exe", "/tmp/evil.exe"]
    };
    for rel in absolute {
        write_manifest(
            &feed,
            &format!(
                r#"{{"version":"2.0.0","binary":"{}"}}"#,
                json_escape(rel)
            ),
        );
        let err = make_plan(&feed, "1.0.0")
            .expect_err(&format!("绝对路径 binary {rel:?} 必须被拒绝"))
            .to_string();
        assert!(
            err.contains("绝对路径") || err.contains("目录穿越"),
            "错误信息应说明原因: {err}"
        );
    }
}

#[test]
fn plan_rejects_http_source_and_missing_dir() {
    let err = make_plan(Path::new("https://example.com/rnpc/feed"), "1.0.0")
        .unwrap_err()
        .to_string();
    assert!(err.contains("HTTP 更新源尚未支持"), "错误信息应明确: {err}");
    assert!(err.contains("本地目录"), "错误信息应给出替代方案: {err}");

    let err = make_plan(Path::new("http://example.com/feed"), "1.0.0")
        .unwrap_err()
        .to_string();
    assert!(err.contains("HTTP 更新源尚未支持"), "http 同样拒绝: {err}");

    let tmp = TempDir::new("no-dir");
    let missing = tmp.join("not-there");
    let err = make_plan(&missing, "1.0.0").unwrap_err().to_string();
    assert!(err.contains("更新源目录不存在"), "错误信息应可读: {err}");

    // 当前版本非法不能被当成"相同"
    let feed = tmp.dir("feed");
    write_manifest(&feed, r#"{"version":"2.0.0","binary":"rnpc.exe"}"#);
    assert!(
        make_plan(&feed, "latest").is_err(),
        "当前版本非法时必须报错"
    );
}

// ---------------------------------------------------------------------------
// 更新计划
// ---------------------------------------------------------------------------

#[test]
fn plan_reports_older_when_update_available() {
    let fx = Fixture::new("plan-older", "1.2.0", Some("ab".repeat(32)));
    let plan = make_plan(fx.feed(), "1.0.0").unwrap();
    assert_eq!(plan.current, "1.0.0");
    assert_eq!(plan.target, "1.2.0");
    assert_eq!(plan.order, VersionOrder::Older);
    assert!(plan.blocked.is_none(), "版本过低才阻塞，这里应放行");
    assert!(plan.binary_present);
    assert_eq!(plan.checksum, Some("ab".repeat(32)));
}

#[test]
fn plan_reports_newer_for_downgrade_feed() {
    // 清单版本比当前更旧：order 是 current 相对 target → Newer，且不阻塞
    let fx = Fixture::new("plan-downgrade", "0.9.0", None);
    let plan = make_plan(fx.feed(), "1.0.0").unwrap();
    assert_eq!(plan.order, VersionOrder::Newer);
    assert!(plan.blocked.is_none(), "降级不在 blocked 范畴，由调用方决定");
}

#[test]
fn plan_reports_same_version() {
    let fx = Fixture::new("plan-same", "1.0.0", None);
    let plan = make_plan(fx.feed(), "1.0.0").unwrap();
    assert_eq!(plan.order, VersionOrder::Same);
    assert!(plan.blocked.is_none());
    assert!(plan.binary_present);

    // 缺段补 0 也算同版本
    let plan = make_plan(fx.feed(), "1.0").unwrap();
    assert_eq!(plan.order, VersionOrder::Same);

    // 本地更新源缺二进制：仅记录，不在计划阶段失败
    fs::remove_file(fx.feed().join("rnpc.exe")).unwrap();
    let plan = make_plan(fx.feed(), "0.9.0").unwrap();
    assert!(!plan.binary_present);
}

#[test]
fn plan_blocks_when_current_below_min_version() {
    let tmp = TempDir::new("plan-min");
    let feed = tmp.dir("feed");
    fs::write(feed.join("rnpc.exe"), b"new").unwrap();
    write_manifest(
        &feed,
        r#"{"version":"2.0.0","binary":"rnpc.exe","min_version":"1.5.0"}"#,
    );

    let plan = make_plan(&feed, "1.4.9").unwrap();
    assert_eq!(plan.order, VersionOrder::Older);
    let blocked = plan.blocked.expect("低于 min_version 必须被标记");
    assert!(blocked.contains("1.5.0"), "原因应提到最低版本: {blocked}");
    assert!(blocked.contains("手动升级"), "原因应说明怎么处理: {blocked}");

    let plan = make_plan(&feed, "1.5.0").unwrap();
    assert!(plan.blocked.is_none(), "等于最低版本时不应阻塞");

    let plan = make_plan(&feed, "1.9.0").unwrap();
    assert!(plan.blocked.is_none());
}

// ---------------------------------------------------------------------------
// 执行更新
// ---------------------------------------------------------------------------

#[test]
fn apply_replaces_binary_and_keeps_backup() {
    let fx = Fixture::new("apply-ok", "2.0.0", None);
    let plan = make_plan(fx.feed(), "1.0.0").unwrap();
    assert!(plan.binary_present);

    let stopped = Cell::new(false);
    let backup = apply(fx.feed(), &plan, fx.dest(), || {
        stopped.set(true);
        Ok(())
    })
    .expect("更新应成功");

    assert!(stopped.get(), "before_replace 必须被调用");
    assert_eq!(backup, backup_path(fx.dest()));
    assert_eq!(backup.file_name().unwrap(), "rnpc.exe.bak");
    assert_eq!(fs::read(fx.dest()).unwrap(), fx.new_bytes, "目标已替换为新内容");
    assert_eq!(fs::read(&backup).unwrap(), fx.old_bytes(), "备份保留旧内容");
    assert_eq!(sha_of(fx.dest()), fx.checksum, "落盘内容与源 sha256 一致");
}

#[test]
fn apply_creates_target_when_missing() {
    let fx = Fixture::new("apply-fresh", "2.0.0", None);
    fs::remove_file(fx.dest()).unwrap();
    let plan = make_plan(fx.feed(), "1.0.0").unwrap();
    let backup = apply(fx.feed(), &plan, fx.dest(), || Ok(())).expect("新装应成功");
    assert_eq!(fs::read(fx.dest()).unwrap(), fx.new_bytes);
    assert!(
        !backup.exists(),
        "目标原先不存在时不应产生备份文件: {}",
        backup.display()
    );
}

#[test]
fn apply_rejects_when_checksum_mismatches() {
    // 清单里的 sha256 格式合法但与文件内容不符
    let fx = Fixture::new("apply-bad-sum", "2.0.0", Some("0".repeat(64)));
    let plan = make_plan(fx.feed(), "1.0.0").unwrap();
    assert!(plan.checksum.is_some());

    let stopped = Cell::new(false);
    let err = apply(fx.feed(), &plan, fx.dest(), || {
        stopped.set(true);
        Ok(())
    })
    .expect_err("checksum 不符必须拒绝更新")
    .to_string();

    assert!(err.contains("sha256 校验失败"), "错误应说明校验失败: {err}");
    assert!(!stopped.get(), "校验失败发生在停实例之前，不应调用回调");
    assert_eq!(fs::read(fx.dest()).unwrap(), fx.old_bytes(), "原文件不得被改动");
    assert!(
        !backup_path(fx.dest()).exists(),
        "校验失败不应产生备份"
    );
}

#[test]
fn apply_rejects_when_before_replace_fails() {
    let fx = Fixture::new("apply-stop-fail", "2.0.0", None);
    let plan = make_plan(fx.feed(), "1.0.0").unwrap();

    let err = apply(fx.feed(), &plan, fx.dest(), || {
        Err(anyhow!("停实例失败（模拟）"))
    })
    .expect_err("回调失败必须中止更新")
    .to_string();

    assert!(err.contains("停实例失败"), "应保留回调错误: {err}");
    assert_eq!(fs::read(fx.dest()).unwrap(), fx.old_bytes(), "原文件不得被改动");
    assert!(
        !backup_path(fx.dest()).exists(),
        "回调失败不应产生备份"
    );
}

#[test]
#[cfg(windows)]
fn apply_rolls_back_when_replace_fails() {
    let fx = Fixture::new("apply-rollback", "2.0.0", None);
    let plan = make_plan(fx.feed(), "1.0.0").unwrap();

    // Windows：只读属性会让覆盖写失败（备份只是读，仍然成功）
    let mut perms = fs::metadata(fx.dest()).unwrap().permissions();
    perms.set_readonly(true);
    fs::set_permissions(fx.dest(), perms).unwrap();

    let err = apply(fx.feed(), &plan, fx.dest(), || Ok(()))
        .expect_err("目标只读时替换应失败")
        .to_string();

    assert!(err.contains("已还原"), "错误必须说明已还原: {err}");
    assert_eq!(
        fs::read(fx.dest()).unwrap(),
        fx.old_bytes(),
        "还原后必须恢复旧内容"
    );
    let backup = backup_path(fx.dest());
    assert!(backup.is_file(), "备份应存在: {}", backup.display());
    assert_eq!(fs::read(&backup).unwrap(), fx.old_bytes());
}

#[test]
#[cfg(unix)]
fn apply_rolls_back_when_replace_fails() {
    use std::os::unix::fs::PermissionsExt;

    let fx = Fixture::new("apply-rollback", "2.0.0", None);
    let plan = make_plan(fx.feed(), "1.0.0").unwrap();

    // 目标文件只读 → 覆盖写失败（备份只读，仍然成功）
    fs::set_permissions(fx.dest(), fs::Permissions::from_mode(0o444)).unwrap();

    let err = apply(fx.feed(), &plan, fx.dest(), || Ok(()))
        .expect_err("目标只读时替换应失败")
        .to_string();

    assert!(err.contains("已还原"), "错误必须说明已还原: {err}");
    assert_eq!(
        fs::read(fx.dest()).unwrap(),
        fx.old_bytes(),
        "还原后必须恢复旧内容"
    );
}

#[test]
fn apply_refuses_same_version_and_blocked_plan() {
    let fx = Fixture::new("apply-same", "1.0.0", None);
    let plan = make_plan(fx.feed(), "1.0.0").unwrap();
    assert_eq!(plan.order, VersionOrder::Same);
    let err = apply(fx.feed(), &plan, fx.dest(), || Ok(()))
        .expect_err("同版本不应执行替换")
        .to_string();
    assert!(err.contains("无需更新"), "错误信息应可读: {err}");
    assert_eq!(fs::read(fx.dest()).unwrap(), fx.old_bytes());

    // 被阻塞的计划同样拒绝执行
    let tmp = TempDir::new("apply-blocked");
    let feed = tmp.dir("feed");
    fs::write(feed.join("rnpc.exe"), b"new").unwrap();
    write_manifest(
        &feed,
        r#"{"version":"2.0.0","binary":"rnpc.exe","min_version":"1.5.0"}"#,
    );
    let dest = tmp.dir("bin").join("rnpc.exe");
    fs::write(&dest, b"OLD").unwrap();
    let plan = make_plan(&feed, "1.0.0").unwrap();
    let err = apply(&feed, &plan, &dest, || Ok(()))
        .expect_err("blocked 计划不应执行")
        .to_string();
    assert!(err.contains("拒绝更新"), "错误信息应可读: {err}");
    assert_eq!(fs::read(&dest).unwrap(), b"OLD");
}

#[test]
fn apply_refuses_when_feed_changed_after_plan() {
    let fx = Fixture::new("apply-toctou", "2.0.0", None);
    let plan = make_plan(fx.feed(), "1.0.0").unwrap();

    // 计划与执行之间清单被替换成别的版本
    write_manifest(fx.feed(), r#"{"version":"3.0.0","binary":"rnpc.exe"}"#);

    let err = apply(fx.feed(), &plan, fx.dest(), || Ok(()))
        .expect_err("清单变化后应拒绝执行")
        .to_string();
    assert!(err.contains("发生变化"), "错误信息应可读: {err}");
    assert_eq!(fs::read(fx.dest()).unwrap(), fx.old_bytes());
    let _ = fx.temp();
}
