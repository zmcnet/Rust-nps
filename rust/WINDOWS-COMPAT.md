# Windows 兼容性：实测结论

本文记录 `rnps` / `rnpc` 在 Windows 上能跑多老，以及**为什么**。所有结论都来自对本机
产物的 PE 导入表解析（`scripts/pe_imports.py`），不是推测。

## 结论速览

| 目标 | 能否运行 | 依据 |
| --- | --- | --- |
| Windows 11 / 10（含 LTSC、Server Core） | ✅ 可以 | 所有依赖 API 在 Win10 均存在 |
| Windows 8.1 / 8 | ❌ 不能 | 需要 `ProcessPrng`（Win10+） |
| Windows 7 SP1 | ❌ 不能 | 需要 `ProcessPrng`（Win10+） |
| Windows Vista | ❌ 不能 | 同上，且 std 另有 Win8+ 依赖 |
| Windows XP SP3 | ❌ 不能 | Rust 无 XP target，且上述依赖全部缺失 |

**最低支持基线：Windows 10。** 这是 Rust 标准库自身的下限，不是本项目可以绕过的选择。

## 硬事实一：Rust std 本身就要求 Win10

用一个**零依赖、纯 std** 的程序做对照实验：

```rust
fn main() { println!("hello"); }
```

静态 CRT 构建后的导入表：

```
ntdll.dll
api-ms-win-core-synch-l1-2-0.dll
    WakeByAddressAll
    WakeByAddressSingle
    WaitOnAddress          ← Win8+
```

再加上 `std::collections::HashMap`：

```rust
use std::collections::HashMap;
fn main() { let mut m = HashMap::new(); m.insert(1u64, 2u64); println!("{:?}", m.get(&1)); }
```

导入表多出：

```
bcryptprimitives.dll
    ProcessPrng            ← Win10+
```

**原因**：Rust 1.78 起把 Windows 最低支持版本明确提升到 Windows 10。
`HashMap` 的 `RandomState` 需要密码学随机种子，std 在 Windows 上直接调用 `ProcessPrng`；
线程 park/unpark 使用 `WaitOnAddress`。这两处都在 std 内部，无法通过 feature 关闭。

## 硬事实二：这不是我们的依赖造成的

分别测试各依赖的最小组合，`api-ms-win-core-synch-l1-2-0.dll` 始终存在：

| 构建组合 | 是否导入 Win8+ synch | 是否导入 ProcessPrng |
| --- | --- | --- |
| 纯 std（空 main） | 是 | 否 |
| 纯 std + HashMap | 是 | **是** |
| `mio` 单独（net + os-poll） | 是 | 否 |
| `tokio`（net + rt） | 是 | 是 |
| `rnps` 完整（axum + tokio + tracing） | 是 | 是 |
| `rnpc` 完整（tokio + nps-legacy） | 是 | 是 |

即：**即使把 tokio / axum 全部去掉，Win8+ 依赖依然存在**。削减依赖不能降低版本下限。

## 已做且有效的优化：静态 CRT

`.cargo/config.toml` 对 Windows target 启用 `-C target-feature=+crt-static`，效果实测：

**之前**（动态 CRT）：
```
VCRUNTIME140.dll          ← 需要装 VC++ 运行库
api-ms-win-crt-heap-l1-1-0.dll
api-ms-win-crt-runtime-l1-1-0.dll
api-ms-win-crt-stdio-l1-1-0.dll
api-ms-win-crt-string-l1-1-0.dll
api-ms-win-crt-locale-l1-1-0.dll
api-ms-win-crt-math-l1-1-0.dll
```

**之后**（静态 CRT）：
```
kernel32.dll
ntdll.dll
ws2_32.dll
api-ms-win-core-synch-l1-2-0.dll
bcryptprimitives.dll
```

只剩 5 个系统 DLL，**不再需要 VC++ 运行库**。这是「装到干净机器上就能跑」的关键一步：
Windows 10 全新安装、LTSC、Server Core 都自带这 5 个。

产物大小：`rnps` 3.6 MB，`rnpc` 2.2 MB（release，未 strip）。

## 关于 Windows 10 LTSC / 无 VC 库环境

LTSC 与 Server Core 删掉的是 Store、Edge、Media Foundation 等上层组件，**Win32 API 与系统
DLL 完整保留**。因此静态 CRT 之后，本项目的产物在这些环境可直接运行，不需要任何额外安装。

## 关于 XP：不可行，以及替代路径

XP 不可行有三重原因，任一都足以否决：

1. Rust **从未**提供 XP target（`rustc --print target-list` 无任何 `*xp*`）。
2. XP 缺少 `WaitOnAddress`（Win8+）与 `ProcessPrng`（Win10+），而它们来自 std。
3. 即便用 tier-3 的 `x86_64-win7-windows-msvc` + nightly `build-std`，也只能把目标降到
   Win7，且需要给 std 打补丁替换这两处 API——属于维护一个 Rust 分支的工作量。

**若必须覆盖 XP，建议按以下顺序取舍：**

| 方案 | 成本 | 说明 |
| --- | --- | --- |
| XP 用户继续用原版 Go `npc` | 零 | 服务端是 Rust，客户端仍可用原版；协议完全兼容 |
| 为 XP 单独维护一个 Go 客户端 | 中 | Go 1.x 仍支持 XP（1.10 及更早）；只需客户端，工作量远小于全平台 |
| 打补丁维护 Rust std 分支 | 高 | 需长期跟进上游，不推荐 |

当前项目的选择是**第一条**：Rust 服务端 + 原版 Go 客户端，XP 用户不受影响。

## 如何自行复核

```powershell
# 构建
cargo build --release -p nps-app --bin rnps

# 解析导入表（纯标准库，无需第三方依赖）
python scripts/pe_imports.py target/release/rnps.exe
```

`scripts/pe_imports.py` 直接解析 PE 的 Import Directory，输出每个 DLL 及其函数名。
用它对比任意构建产物，即可确认上面所有结论。

## 未验证项

- 本文所有结论来自 **PE 导入表静态分析**，未在真实 Win8.1 / Win7 / XP 机器上启动验证
  （本机只有 Windows 11）。静态导入缺失会导致加载器直接失败，这一因果关系是确定的；
  但若需要 100% 实证，应在目标系统上实际运行一次。
- Windows ARM64 未构建验证。
- 计划任务、Windows 服务等自启通道需要管理员权限，开发机为非管理员，未实测成功路径。
