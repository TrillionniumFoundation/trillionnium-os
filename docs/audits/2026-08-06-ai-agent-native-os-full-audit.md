# Trillionnium OS AI Agent Native 全量架构审计与整改基线

日期：2026-08-06

审计基线：`p0-agent-native-integration-20260731@f793345` 及同日 Android/真机工作状态

结论等级：**P0 源码原型；不具备产品发布资格**

## 1. 执行结论

审计基线按“能否交付一个可启动、可复现、可审计、能完成真实任务的
Codex-native OS”计约 **35/100**。本轮已经完成大范围 Codex-only
源码整改，但这没有把系统自动提升为可发布产品；最终状态仍是 **P0 源码原型**：

- **方向正确**：手机不承载本地 LLM；Codex 是唯一内置 Agent，推理由外部模型服务完成。
- **源码整改已完成**：control-plane、Android product declarations、AiShell、
  AiAuthority、SDK 和 SELinux 的活动权限图已经收敛到 Codex-only；OpenClaw
  专属 packaging/vendor 物料和旧双 Agent RootFS 工具已做可恢复外部归档后移出活动树。
- **产品材料化仍失败关闭**：Android 已检入的 common/P01 工具 ELF 和 rootfs
  daemon 仍含旧双身份字节或早于 capability hardening。Soong 已增加 11 个旧身份
  负向门禁，因此这些旧物料不会被当作 Codex-only 产品静默放行。
- **Root Linux 仅部分完成**：只读挂载、SELinux 和 capability 基础存在，但当前
  rootfs 不干净且守护服务未运行，没有一次真实 Codex Agent turn。
- **shell/ADB 尚未实现**：新的 ADR 和 v2 contract 已接受 Codex 直接调用、OS
  托管传输与权限的方向；backend、transport、ADB key custody 和物理 effect 证据仍为零。
- **Windows 尚未实现**：只有 research custody 资产和 product absence contract，
  不属于当前产品能力。
- **发布仍不合格**：源码、设备 hotpatch、rootfs 与已检入 ELF 尚未形成唯一、
  可复现、签名并通过 OTA/AVB 与掉电回放验证的 BOM。

因此，当前可以声明“**Codex-only source graph 已形成**”，不能声明“Codex-native
手机 Agent 已工作”或“direct shell/ADB 已交付”。

## 2. 审计范围与证据

本次检查覆盖：

- 权威 control-plane 源：`trillionnium-release-sources/p0-agent-native-integration-20260731/trillionnium-os`
- Android 产品树：`android/lineage-fogos`
- `vendor/trillionnium`、`device/trillionnium/sepolicy`、`trillionnium-sdk`
- `TrillionniumAiShell`、`TrillionniumAiAuthority`
- 当前连接的 `fogos` userdebug 真机
- Git 全历史、当前/历史架构文档、contract、evidence、mobile-smoke 与构建/测试脚本

文档和历史清点：

- Git 当前可见 507 个提交。
- `docs/` 共 406 份文件；396 份在活动树、仅 10 份在 `docs/archive`。
- 活动树中 362 份是 2026-05 的 `mobile-smoke`，主要对应 Mobian/Phosh/Waydroid/旧 Shell 路线。
- 活动文档中 160 份仍含 OpenClaw，329 份含 Mobian/Phosh/Waydroid/Hepta 旧方向词项。
- 代码与脚本约 330k 行；若干单文件已超过合理维护边界：
  - `trillionnium-command-center/src/dashboard.rs`：约 40k 行
  - `trillionnium-shell/src/main.rs`：约 32k 行
  - `trillionniumd/src/android_agent_api.rs`：约 15k 行
  - `trillionnium-tool-runtime/src/supervised_codex.rs`：约 11k 行
  - `operation_journal.rs`：约 8.5k 行

以上说明当前主要风险不是“缺少更多 proof 类型”，而是历史路线、巨型模块和产品闭环之间失衡。

## 3. 架构合格度

| 维度 | 当前状态 | 评级 |
| --- | --- | --- |
| 无本地 LLM | README/ADR 已明确，方向正确 | A |
| Codex-only 源码身份 | singleton descriptor、binding、SDK generated contracts 已同步 | SOURCE PASS |
| Android 安装/启动声明 | Soong/product/init/manifest 活动图只引用 Codex | SOURCE PASS |
| Android 已检入 ELF/rootfs | 仍含旧身份字节；11 个 Soong gate 使其失败关闭 | MATERIALIZATION HOLD |
| Codex 生产 turn | production effect constructor/调用链未闭合，真机无 Agent API v2 socket | F |
| Android System API/Accessibility | 有大量 contract、broker 和静态测试，物理 effect 仍 HOLD | C- |
| Codex shell/ADB | 新 ADR 已接受方向；backend/transport/key custody 当前实现为 0 | F |
| Root Linux | 只读挂载与隔离底座存在；rootfs/启动/发布不闭合 | C- |
| Windows | research-only，产品图中不存在 | F |
| Codex-only SELinux/consent 边界 | 活动源码已收敛；最终组合构建和物理证据仍 HOLD | SOURCE PASS |
| 可复现构建/OTA | 多工作树 dirty、rootfs pin 失配、设备 hotpatch 漂移 | F |
| 代码/资产卫生 | 专属旧 Agent 物料已归档；旧 GUI rootfs、研究资产和巨型模块仍待处理 | D |

因此不能把当前状态描述为“AI Agent Native OS 已实现”；准确描述应为：

> 已形成一套重安全契约的 P0 Agent-native 底座，但尚无可工作的 Codex 到手机 effect 的产品纵向闭环。

## 4. Codex-native 正确目标架构

新的权威架构应只有一个内置 Agent：Codex。

1. **Inference plane**：模型推理在远端；设备不下载、加载或调度本地大模型。
2. **Agent plane**：Codex runner 由 OS 安装、度量和监督，运行于最小 Root Linux 环境。
3. **Tool plane**：Codex 直接看到并调用 `shell`、`adb`、Android System API、Accessibility 等第一等工具。
4. **Privilege plane**：直接调用不等于让模型持有永久 ambient root。ADB key、root capability、SELinux transition、超时、cgroup、审计和回放状态由 OS 托管。
5. **Effect plane**：普通操作直接执行；高风险 root/刷写/卸载/隐私读取进入明确的用户确认或 developer-mode policy。

建议将 shell/ADB 分成三个明确层级：

- `shell.exec(argv)`：普通 Root Linux/Android shell，固定 argv，不经隐式 `sh -c`。
- `adb.*`：由 OS 管理本机/外部设备 transport 和 credential，Codex 可直接调用其语义。
- `root.exec(argv)`：显式高权限工具，短时 lease、精确 capability/SELinux 域和完整 receipt。

这仍然符合“Agent 直接使用 ADB/shell 控制手机”的产品体验，同时避免把整个 OS 的 TCB 退化为一个长期 root shell。若产品确实要求 Codex 拥有不受约束的 raw root shell，应在新 ADR 中明确接受相应安全后果，并删除当前所有与之矛盾的安全声明。

## 5. Root Linux 审计

已实现的部分：

- Root Linux、Codex、tool、daemon、`proc` 的只读/`nosuid`/`nodev` 挂载边界已在真机出现；`proc` 另有 `noexec`。
- 持久工具状态使用 `rw,noexec`。
- SELinux enforcing；普通 adb shell 不能读取 Agent 私有执行文件、状态和私有属性。
- capability launcher 的精确 capability 集与 bounding/ambient 清零已有静态和局部测试。

未实现或不合格的部分：

- 真机 `high-water`、ready gate、egress guard、Root Linux daemon 均停止。
- 无 Codex/agentd 活动进程，无 `/run/trillionnium/agent-api-v2.sock`。
- 普通 product dependency 因 checked-in rootfs 内旧 daemon hash 与 product pin 不一致而故意失败。
- 完整 TCB gate 实测在 `current rootfs archive predates capability hardening and must be rebuilt` 处失败。
- Android common/P01 的 System API、Accessibility 和 daemon ELF 仍可检出旧 Agent
  身份字节；它们现在受 Soong 硬门禁约束，不能作为新的 Codex-only rootfs 输入。
- 真机自报 v66，但 wrapper/manifest 对应 v68 hotpatch；不是可追溯 release image。

Rootfs 还存在确定的历史污染：

- 活动 archive 约 378 MB、32k+ members、512 个 installed package records。
- 仍含 Phosh、GNOME、GTK、Xwayland、Squeekboard、PipeWire/WirePlumber 等桌面栈。
- dpkg records 仍把旧 Command Center、Shell、Mobian UI 组件标为 installed。
- 当前 refresh 脚本只是替换旧 archive 中的少数 artifact，不能得到干净最小 rootfs。

结论：必须从 fresh minimal base 以 allowlist 重建，不应继续在旧 Mobian tar 上打补丁。

## 6. Windows 适配审计

Windows compatibility **未实现**：

- 无 Soong runtime/install module。
- 无 product package、init service、Agent descriptor、typed API 或真机证据。
- 活动 vendor tree 中约 231 MB 的 Wine/QEMU/tar 只是 research custody 资产。
- Windows product absence test 当前通过；完整 TCB 的失败点在旧 rootfs，不在 Windows 阶段。

建议：把 Windows research bytes 和三个历史 probe 移出活动 vendor tree，放入外部只读 artifact archive；产品树只保留一个很小的 absence/tombstone contract。未来若重启 Windows 适配，应作为独立 milestone，不应继续让“研究文件存在”被误解为功能进度。

## 7. Codex-only 整改结果与 OpenClaw 退役边界

### 7.1 A0：活动产品入口已切断

- Rust daemon 只保留 Codex provider/identity；旧 adapter、auth 和 schema 已删除。
- AiShell 删除旧 Agent 选择、凭据导入、result/recovery 新建路径；direct evidence
  升为 v2，旧多 Provider recovery 状态失败关闭且不重放。
- AiAuthority 的 egress consent、lease 和 broker 只接受 Codex identity。
- Android SDK 两份 authority contract 与 Rust authority 字节级一致，并通过生成器
  重新生成 singleton Java registry/constants/golden vectors。
- vendor Soong/product/init/bootstrap/runner/egress/manifest 的活动安装与启动图只保留
  Codex；旧 UID/GID 5902 只作为不可复用 tombstone 出现。
- SELinux 已删除旧 Agent 专属 domain/type/exec/data/port/transition；Codex domain、
  UID 5901 和 proxy port 18791 保留。ADB domain 仍为无 transition source 的 inert
  source-only 定义，不构成 direct ADB 实现。

### 7.2 A1：源码契约已单例化，旧二进制尚未重建

- descriptor registry、canonical operation binding、typed catalog、permission model
  和 launch conformance 已收敛为 Codex singleton。
- 活动 Rust `apps/`、`crates/`、`foundations/` 中旧 provider implementation token
  为零；双 Provider cgroup/inventory、packaging 和 RootFS composer 已移除或归档。
- provider post-exec bootstrap 的 recipe、builder、C supervisor、测试和 README 已
  收敛为 Codex 单例；废弃 Node/dynamic-preinit 与非 Codex planner/fallback 分支在
  完整外部快照后删除。Codex-only recipe SHA-256 为
  `f231f9c106394f574692f895f5b35f00dbcdcf3b771b4adda7d563dd664ea4bf`。
  旧 P0-1 双 Provider 页面已改为明确 superseded tombstone。
- privilege-broker 中只为旧第二 provider 服务的 `NodeDynamicPreinit` receipt/ELF
  parser、Node source pins 与 loader closure 也已删除；仅保留 `NODE_OPTIONS`、
  `NODE_PATH` 等通用环境注入 denylist 及其 Codex 负向测试。
- permission model 明确为被 v2 boundary 取代的 typed-candidate HOLD；它不授权
  direct shell/ADB，也不再把 raw ADB 永久排除在产品方向之外。
- 本轮 source authority SHA-256 为：descriptor registry
  `5ecd89d3c9fedbbeb0ac1de32fba2b5e5e5d248048ddc9a9e0359a0a01903119`，canonical
  operation binding `e24a5029cbc545971dc8ca935754faa44df4406bcdc600c7e5fef3b7c8b48231`，
  typed catalog `c4efd224e75bc21ab95753eac4f183732c447e315ac89d4369bc5185a4997453`，
  superseded permission model
  `350677f97a40935c866f59fd822d76a92a18cfbf1265733ba71c5dd152fb155a`；v2
  boundary SHA-256 为
  `33febe268d6b263bdc23f852b40baaf765fb09d17293baad71867b3c06323150`。
- direct Agent host ABI SHA-256 为
  `9cc631b5a2dc089e8f10b5b16240024f59d7c57e8321666fca29d4aeae08773e`。
  live health 已明确区分 wire method declaration、source-only materialization HOLD
  与 `runtime_ready=false`，不能再把接口存在误读为真机 Agent turn 可用。
- 这只是 **source pass**。六类已检入 ELF 已确认仍含旧身份字节或不满足当前
  authority：common System API、common Accessibility、P01 System API、P01
  replay-sync、P01 daemon 和 rootfs daemon。旧 rootfs archive 也尚未重建。
- `prebuilt/common/Android.bp` 中 11 个 product-path genrule 现在对上述旧身份字节
  做硬拒绝；因此最终状态是 **Codex-only source/product declarations PASS，真实
  ELF/rootfs materialization HOLD**，不是通过修改 receipt 或 pin 伪造成功。

### 7.3 OTA 迁移边界有意保留

旧设备可能仍有 UID 5902、bind mount、SQLite/auth/state/inbox 和旧 Agent rootfs
文件。vendor 已保留一个精确、固定范围的迁移版本边界：

- stop worker/daemon 后只 unmount 10 个固定旧 bind path；
- 使用 no-follow/openat 语义和固定 allowlist 隔离旧 state/inbox；
- UID/GID 5902 保留为 retired tombstone，不可立即复用；
- 禁止宽泛递归删除或跟随符号链接；
- 完成双 Agent 到 Codex-only 的真实 OTA、重启、掉电和残留扫描后，下一版才可
  删除迁移逻辑与 tombstone。

## 8. 冗余、归档与仍待清理项

### 8.1 已移出活动树并可恢复归档

所有归档均位于源码/构建树之外的
`/home/qian-qi/trillionnium-retired-artifacts/2026-08-06/`，不得作为产品输入：

- `trillionnium-openclaw-packaging-retired-20260806.tar.zst`

  SHA-256 `64d6c58aaf295a50c6e0b76208195b369fe65e65b44c6fa0c9a87ac1d09cba13`
- `trillionnium-vendor-openclaw-retired-20260806.tar.zst`

  SHA-256 `154b2040f54ca51ccb88baf913d4cbf4213dd16f397ea20e62674cadc2a20233`
- `trillionnium-dual-agent-rootfs-tools-retired-20260806.tar.zst`

  SHA-256 `1977f95f5f604ba5a250d7664f4aeb7f1fb0053f5f2c9941caf2df7ab6d55ce7`
- `trillionnium-dual-agent-rootfs-python-retired-20260806.tar.zst`

  SHA-256 `89c25cf2d86799cc98e0516ff853c1ffbaa1b3045638064436d00b938213f033`
- `trillionnium-dual-provider-bootstrap-retired-20260806.tar.zst`

  SHA-256 `25f5d4ca84878cf8aa6b9e5bfb322d346c5cfb968eba57382311a43aa11a1d83`

这些归档分别保留旧 control-plane packaging、Android vendor runtime/P01 物料、
双 Agent RootFS composer/EROFS 测试、孤立 admission/reproducibility Python 工具，
以及 provider post-exec bootstrap 的完整退役前快照。
活动产品树不再安装或启动它们；Git 历史未重写。

### 8.2 仍待移出或重建

- 两个无产品引用的 Mobian tar（约 257 MB）。
- WindowsCompat research bytes（约 231 MB）；最终活动产品树只应保留 absence contract。
- 当前 rootfs 内 Phosh/GNOME/Xwayland/Squeekboard、旧 Shell/Command Center 包和
  package records；必须从 fresh minimal allowlist base 重建，不能在旧 tar 上继续减包。
- 已含旧身份字节的 common/P01 ELF；必须从当前 Codex-only authority 真构建，
  更新精确 digest/receipt 后再进入 rootfs 与 product graph。
- 旧 workspace clone；它与权威源码有数千个 only-in-old/untracked 文件，禁止反向 merge。

### 8.3 应移入 archive/evidence，不应继续作为当前说明

- 全仓文字扫描仍会命中约 168 个 OpenClaw 路径，主体是下列历史文档/evidence，
  以及 OTA retirement、absence/negative test 中必须保留的旧身份字面量；这不等于
  产品 principal 仍可达，也不能误报为“Git 工作树全文 token 为零”。
- 362 份旧 `docs/mobile-smoke`。
- 双 Agent ADR、旧 proof、旧 v42/v66 hotpatch receipt。
- Mobian/Phosh/Waydroid/Hepta 实验说明和旧 packaging tests。

### 8.4 应重构而非直接删除

- `android_agent_api.rs`：按 API domain 拆分。
- `supervised_codex.rs`：拆出 provider-neutral supervision、Codex protocol 和 effect bridge。
- `operation_journal.rs`：分离 durable store、state machine、receipt codec 和 replay。
- `trillionnium-command-center`/`trillionnium-shell`：从默认 workspace/product closure 退出；若仍需历史诊断能力，放入 `tools/archive` 或独立仓库。

## 9. 实测门禁

### 9.1 本轮 Codex-only 源码回归

Control-plane：

- `cargo fmt --all`、`cargo check --workspace --all-targets --no-default-features`：PASS。
- `trillionniumd --no-default-features`：345 passed、1 ignored、0 failed；迁移过程中
  暴露的 13 个旧双 Provider fixture/契约假设已逐项修正，没有通过放宽生产验证绕过。
- v2 shell/ADB/Windows boundary：7/7 PASS。
- typed catalog + permission model：8/8 PASS。
- Codex-only P01 launcher/receipt builder：5/5 PASS。
- provider post-exec bootstrap：builder 96 PASS、2 个既有 opt-in smoke SKIP；
  supervisor 8/8 PASS，C17 `-Wall -Wextra -Werror -Wconversion -Wshadow` 检查通过，
  recipe verifier PASS。
- privilege-broker：95 个 lib、1 个 ancillary、2 个 startup 测试均 PASS；Codex-only
  final-payload receipt 定向测试在默认与 `--all-features --lib` 下均为 5/5 PASS。
  完整 all-features binary 仍因未提供 P01 compile-time variant 环境变量而失败关闭，
  不属于本次 receipt 清理回归。
- standalone typed exec/ADB broker：35/35 PASS；该 foundation 没有 listener、
  backend 或 product authority，ADB 请求仍返回 HOLD，不能据此声明 direct ADB 已实现。
- 两组重点 Python contract 共 115 项执行：114 PASS、1 个按设计 SKIP；跳过项要求
  外部真实 v3 artifact set，未用伪 receipt 绕过。
- 全 workspace 并行回归曾在
  `trillionnium-tool-runtime::timeout_cleans_an_observed_descendant_that_escaped_with_setsid`
  出现一次时序性 timeout；精确复跑、该 package 129/129，以及报告收口时独立执行
  的 `cargo test --workspace --all-targets --no-default-features` 均 PASS；最终
  `trillionniumd` 为 346 passed、1 ignored、0 failed。

Android apps/SDK/SELinux：

- AiShell：security contract PASS，JUnit 26/26；4 个 AOSP host module 和完整 APK
  曾在 Host ABI health 字段最终收敛前通过。最终生成的 Java contract 已与新 Host
  ABI hash 同步，但新的完整 APK 构建展开为 11,841-task 全树依赖后主动中止；旧
  APK hash 不作为当前最终材料化证据，未发现任务代码编译错误。
- AiAuthority：4 个 shell/security contract PASS，JUnit 26/26，3 个 AOSP host
  module PASS；完整 `atest`/APK 因额外拉起 Tradefed/Cronet 大规模依赖而中止，
  没有取得最终 APK 证据。
- SDK：descriptor/binding generator `--check`、registry/binding/System API/
  Accessibility contract 均 PASS；System API JUnit 70/70。Accessibility JUnit
  最终按 `java_test_host` 精确同源清单复编译为 66/66 PASS；AOSP Soong host module
  因共享 `out/.lock` 未进入材料化，仍为 build HOLD。
- SELinux：broker 7/7、issuer 6/6、source-only replay 10/10 PASS；此前注入同轮生成
  的 platform/system_ext CIL 后完整 replay gate 11/11 PASS，且 system_ext CIL 生成
  成功。最终组合 `secilc`、Ninja 与安装步骤未取得终态成功记录，仍为构建证据 HOLD。

Android vendor：

- Codex-only source/product declarations、retired-provider absence/migration、
  WindowsCompat absence、bootstrap transaction、no-rootfs-mutation、shell/C++ syntax
  与 Blueprint parse/format：PASS。rootfs state migration 在前序完整环境曾 PASS；
  报告收口时单独复跑因缺少未检入的 host `toybox` 在测试前置阶段停止，未进入迁移
  断言，当前环境证据记为 HOLD 而不是源码断言 FAIL。
- 11 个 Soong product-path hard negative gate 已存在，并被 product module 依赖；
  它们会拒绝 `openclaw|open_claw|5902` 字节。
- direct product audit：按设计 FAIL 于 common System API 旧 ELF。
- production TCB：按设计 FAIL 于旧 rootfs daemon 早于 capability hardening。

### 9.2 仍有效的设备与环境证据

- 真机 SELinux enforcing，但 high-water、ready gate、egress guard、Root Linux daemon
  均停止，无 Codex/agentd 活动进程和 Agent API v2 socket，无法执行最终 Agent turn。
- 真机 v66 与 v68 hotpatch 物料混用，不构成发布 BOM。
- 报告收口时执行 `python3 -m unittest discover -s tools/tests -p 'test_*.py'`：
  260 项中 227 PASS、27 FAIL、5 ERROR、1 SKIP。32 个失败/错误均在 Mobian
  production artifact gate，并由 source-bound control file 为 group-writable
  （当前为 0664/0775）这一 owner/mode 前置条件提前失败触发；不是本轮 Codex-only
  contract 断言回归。本轮没有用全树 `chmod` 制造大规模无关 mode diff；必须在
  owner-controlled clean checkout/build 环境重新取得该 production-mode 门禁结果。

最终发布必须同时满足：

1. clean source tree、唯一 BOM、唯一版本/fingerprint；
2. clean target-files/OTA/AVB；
3. target-files 中 OpenClaw、Mobian GUI、Windows Wine/QEMU 为零；
4. 开机后 Codex runner/daemon/guard/ready 状态正常；
5. 实际完成 Codex turn → shell/ADB/System API effect → ACK/compact → daemon restart → reboot/power-loss replay；
6. 安全负向测试证明普通 app/adb shell 无法绕过 broker 或读取 Agent 私有状态。

## 10. 最短整改顺序

1. 冻结当前 hotpatch，统一权威源码、Android vendor、sepolicy、SDK 与设备版本/BOM。
2. 在 clean builder 从当前 Codex-only authority 重建 common/P01 ELF，替换旧
   rootfs artifact，生成真实 receipt/digest 并让 11 个 hard gate 与 production TCB 通过。
3. 从 fresh minimal base 重建 Root Linux/rootfs，彻底移除 GUI/旧包污染。
4. 先打通一个最小但真实的 Codex turn 和 Android effect，再继续扩展 proof/custody 类型。
5. 实现 OS-owned shell/ADB transport、credential、SELinux/cgroup/audit；分别验证
   standard、elevated 与 destructive policy，不把已有 inert ADB binary 当作完成证据。
6. 在真实旧双 Agent 设备上验证固定 allowlist OTA cleanup、重启、掉电和残留扫描，
   之后才删除迁移代码与 UID/GID 5902 tombstone。
7. clean build、target-files、OTA、AVB、物理重启/掉电/replay 全部通过后，才可
   宣布 AI Agent Native OS 达标。

## 11. 本次审计限制

本轮没有启动停止中的 Agent 服务、没有执行 `adb root`、没有写入/刷写/清理
真机，也没有把当前 dirty hotpatch、旧 ELF 或旧 rootfs 伪装成 release 证据。

本轮完成的是 Codex-only **源码/产品声明图**整改和可恢复旧物料归档；没有完成
新的 common/P01 ELF/rootfs 材料化，没有实现 direct shell/ADB backend，也没有
取得 clean target-files/OTA/AVB 或物理 Agent effect 证据。测试 PASS 只证明其明确
覆盖的源码/契约边界，不能替代上述产品与真机门禁。
