# Trillionnium OS AI Agent Native 全量架构审计

日期：2026-07-23
性质：时点审计证据，不替代 `docs/CURRENT_STATE.md` 与 canonical ADR。

## 1. 审计口径

本次按以下产品定义审计：

- 手机不运行本地 LLM，也不以本地推理为发布条件；
- Codex、OpenClaw 是 OS 内置、独立度量的 Agent principal；
- OS 负责 Agent 生命周期、上下文、出网、资源和结果托管；
- Agent 在模型回合内调用 OS-owned、typed、policy-controlled Tool API 操作手机；
- Agent 不获得 adb、root、任意 shell、任意 Binder 或 Android backend 身份；
- Root Linux 是 Android 管理的 headless Agent runtime rootfs，不是第二套手机桌面系统；
- Windows 兼容必须有真实产品模块、监督器、Agent 接入、typed API 和设备证据，不能由 Wine/QEMU 素材代替。

规范依据：

- `docs/CURRENT_STATE.md:13`
- `docs/architecture/2026-07-20-direct-agent-native-os.md:26`
- `docs/architecture/2026-07-20-direct-agent-native-os.md:35`
- `docs/architecture/2026-07-20-direct-agent-native-os.md:47`
- `docs/architecture/2026-07-20-direct-agent-native-os.md:99`

## 2. 执行结论

结论必须分四层表达：

1. **产品定义与目标架构：合格。** Direct Agent Native 路线正确，且已明确排除手机本地 LLM、Mobian/Phosh 主系统、Agent root/adb/shell，以及旧 plan-to-Authority effect executor。
2. **源码级 OS/Agent 边界：基本合格。** Codex/OpenClaw、Root Linux、Agent Host、System API、Accessibility、SELinux、identity registry、egress 和 replay 基础均有真实实现。
3. **通用手机操控产品：不合格。** 当前只能完成低风险子集，普通 `observe -> click/type -> verify` 任务闭环仍被 capability lease、effect custody 和真实设备门禁阻断。
4. **发布状态：不合格。** 没有 clean full product build、匹配的 Root Linux daemon payload、当前 OTA/install、锁定生产信任根或真实设备 direct-result conformance。

建议评分：

- 架构方向：8/10
- OS mediation 与源码边界：7/10
- 通用手机任务完成度：3/10
- Root Linux 发布完成度：4/10
- Windows 产品完成度：0/10
- 设备/OTA/发布准备度：2/10
- 综合成熟度：约 5/10，定位应为 **内部 Alpha / source-integrated security prototype**。

## 3. Canonical 架构判断

当前真实路径是：

```text
TrillionniumAiShell
  -> trillionniumd Agent Host control
  -> Root Linux 中受监督的 Codex 或 OpenClaw 回合
  -> MCP stdio OS Tool API
       -> measured System API adapter -> Android System API backend
       -> measured Accessibility adapter -> Android Accessibility backend
  -> strict tool evidence + direct result
  -> daemon/AiShell durable recovery state
```

这条路径符合 Agent Native OS 的核心定义。模型不直接获得 Android 权限；adapter 在 backend I/O 前做 typed validation 和固定身份 risk policy，Android backend 再验证固定 Agent/工具身份。

旧的 `plan -> approval -> Authority execute/undo` 已被 canonical ADR 明确废弃。缺少该旧链路不是缺陷，也不应恢复 generic Authority executor。真正需要的是 Direct effect 的 OS action lease、evidence、journal 和 outer custody。

证据：

- `docs/architecture/2026-07-20-direct-agent-native-os.md:47`
- `docs/architecture/2026-07-20-direct-agent-native-os.md:57`
- `docs/architecture/2026-07-20-direct-agent-native-os.md:99`
- `docs/architecture/2026-07-20-direct-agent-native-os.md:122`
- `docs/architecture/2026-07-20-direct-agent-native-os.md:183`

### 已成立的核心基础

- Codex/OpenClaw 是固定 UID/GID、SELinux domain、launcher/runtime digest 和 tool closure 的 OS built-in principals。
- Direct tools 是 measured MCP stdio executables，模型不能选择 backend、socket、身份或风险级别。
- `AgentSystemApiService` 已由 `TrillionniumSystemServer` 在 boot 配置中注册：`/home/qian-qi/android/lineage-fogos/trillionnium-sdk/trillionnium/res/res/values/config.xml:96`。
- System API 已实现 kernel-authenticated peer、持久 replay 和 `launch_package`：`/home/qian-qi/android/lineage-fogos/trillionnium-sdk/trillionnium/lib/main/java/org/trillionnium/platform/internal/AgentSystemApiService.java:51`。
- Accessibility backend 已实现 snapshot/click/text/scroll/global/gesture/batch 的 typed wire；生产 risk guard 决定哪些可到达。
- Agent task/context/memory、egress consent、provider recovery 和 durable result 已有 substantial source implementation。

### 架构债务

- Built-in Direct Agent 与通用 `trillionnium.agent-api.uds.v2` 已共享冻结的 `org.trillionnium.direct-agent-host.abi.v1` lifecycle/result contract；通用 carrier 仍不承载内置 Direct turn，且两者 peer authentication、socket 与 replay trust domain 保持独立。
- `PlanningRequest`、`plan_attempt`、`plan_dispatched`、`local-plan-saga` 等旧术语仍存在，容易让代码和文档重新滑回已废弃架构。
- active health/result 中误导性的 `tool_execution_owned_by_os` 已退役并拆成四个独立事实：Agent owns invocation、OS owns typed backend、daemon 不是 effect executor、Host ABI 不授予 effect authority。旧字段仅允许留在测试隔离的历史 plan 向量与审计说明中。
- AgentDescriptor 已生成 Java/Rust registry，但 init、shell wrapper、Make/manifest 中仍有手工身份/摘要镜像；最终应从一个签名 registry 生成所有产品片段。

### P0.2 Direct Agent Host ABI 收口证据

- canonical contract：`crates/trillionnium-os-types/contracts/direct-agent-host-abi-v1.json`
- raw SHA-256：`97f3cc966459fcac92dc84f658f97283a30d4d3a9d923212e09211bc13d6aeae`
- 生成目标：Rust `direct_agent_host_abi.rs`、AiShell `DirectAgentHostAbi.java`；vendor JSON mirror 与 canonical bytes 相同。
- 两条 health 面嵌入同一个 generated `direct_agent_host` 对象，并由 Rust 跨 carrier 测试逐字段比较。
- Direct result schema 为 v1/44 字段，canonical receipt 为 v2/26 字段；AiShell、daemon 和 vendor fixture 由同一字段集合约束。
- built-in `plan` 仅作为历史 wire/replay 名映射到 `run_direct_turn`；本批没有迁移 durable state、合并 trust domain、开启 Binder、能力租约或任何 effect authority。

## 4. 阻断 Agent 直接操控手机的 P0

### P0-A：Capability lease 未产品化

当前默认 ALLOW 仅覆盖：

- `launch_package`
- metadata-only accessibility snapshot
- scroll
- Back/Home
- 所有成员均为低风险时的 bounded batch

当前 DENY/HOLD 包括：

- `open_uri`
- full-text snapshot
- click
- `set_text`
- gesture
- recents/notifications/quick settings 等敏感 global action
- screenshot、power/lock 等未形成 typed product capability 的动作

`AgentSystemApiService` 对 `open_uri` 明确返回 `capability_lease_unavailable`：`/home/qian-qi/android/lineage-fogos/trillionnium-sdk/trillionnium/lib/main/java/org/trillionnium/platform/internal/AgentSystemApiService.java:194`。

Lease issuer、broker、token/replay、verifier、KeyMint/attestation 和 consumer 有大量 source/package foundation，但没有生产 service instance、trusted pins、root journal/token/ACK producer、measured consumer 或设备 trust material。状态应保持 `SOURCE PASS / PRODUCT HOLD`。

### P0-B：Direct effect outer custody 未激活

Backend 级 same-request replay 是优点，但默认产品未启用 `trusted-context-hotpath`，adapter 不消费 daemon 发布的 per-turn binding inbox。operation journal、outer ACK、daemon custody instance 和跨 provider/daemon crash 的 exactly-once/turn attribution 仍是 inert/source-only。

因此当前能证明部分 backend 请求的幂等性，不能完整证明一个 Agent turn 在响应丢失、进程崩溃、重启或存储异常下的 effect 归属和最终状态。

### P0-C：Kernel process custody 未激活

pidfd measured exec、固定 cgroup leaf、no-descendant proof、secure first-use journal 和 custody-v3 recovery 已有源码与测试，但所有 activation flags 为 false，缺少 authenticated supervisor、root-FD provenance、seccomp、init/SELinux/client 和 live store/spawn wiring。

### P0-D：没有真机闭环证据

当前设备/镜像证据仍是 unlocked/orange、测试 AVB 或内部 DSU 预备状态。没有生产锁定 AVB、兼容 KeyMint/attestation、当前安装、OTA、power-loss/ENOSPC/rollback 和 Codex/OpenClaw 真实 direct-result conformance。

## 5. Root Linux 适配结论

**判断：源码和产品接线已实现；发布适配未实现。**

已实现：

- Android init 创建 Root Linux/state/inbox，验证并挂载 rootfs；
- egress guard 在 daemon 前启动；
- daemon、Agent runtime 和 direct tools 通过受限 mount 进入 rootfs；
- Codex/OpenClaw 使用独立 UID/GID/SELinux domain；
- product runner 只接受 `/usr/bin/trillionniumd`，没有通用 `/bin/sh` fallback；
- vendor product graph 已列入 daemon、rootfs、Codex、OpenClaw、System API 和 Accessibility：`/home/qian-qi/android/lineage-fogos/vendor/trillionnium/config/common.mk:181`。

未实现/阻断：

- checked-in rootfs 内 daemon 摘要为 `5723e663...`，product pin 要求 `d315bc06...`；verified extractor 正确拒绝；
- 新 AArch64 PIE 仅是 dirty-source candidate，不是可发布 payload；
- 长期 daemon 仍以 root/coredomain/mlstrustedsubject 运行并保留 `chown/kill/setgid/setpcap/setuid` 与网络能力；这是当前最大 TCB，最终应把必要特权下沉到最小 broker，使 Host daemon 非 root 化；
- builder pins、external epoch/high-water authority 和 production trust material 为空；
- Android product graph 对 mismatch 是 intentional fail-closed：`/home/qian-qi/android/lineage-fogos/vendor/trillionnium/prebuilt/common/Android.bp:50`；
- rootfs module 明确依赖该失败 gate：`/home/qian-qi/android/lineage-fogos/vendor/trillionnium/prebuilt/common/Android.bp:686`；
- 没有 clean full build、target-files、OTA、安装或真机运行证明。

所以 Root Linux 不能说“没做”，也不能说“已完成”。准确表述是：**SOURCE/PRODUCT-CONTRACT PASS，DAEMON ARTIFACT/DEVICE/RELEASE HOLD**。

## 6. Windows 适配结论

**判断：未实现。**

现有约 231 MiB Wine/QEMU runtime assets、materialized overlay 与历史 app-matrix/notepad/materialize 脚本只是 research custody。它们没有：

- installable/runtime Soong module
- init service
- product package 或 inherit path
- production supervisor
- AgentDescriptor 或 Agent Host access path
- typed OS Tool API
- 文件、剪贴板、显示、音频、网络、持久化、恢复和升级语义
- device/OTA/release conformance

产品配置明确将 WindowsCompat 排除所有 variant：`/home/qian-qi/android/lineage-fogos/vendor/trillionnium/config/common.mk:210`。Soong 只保留 absence contract test：`/home/qian-qi/android/lineage-fogos/vendor/trillionnium/prebuilt/common/Android.bp:717`。

建议二选一：

1. 产品仍需要 Windows：重做为 small supervised service + signed declarative app allowlist + typed launch/inspect API + lease/journal/evidence；
2. 近期不需要：把 231 MiB research assets 和 shell matrix 移出 active vendor tree，保留 hash manifest 和外部归档。

## 7. 冗余、重复与结构问题

### 默认构建图仍混入历史产品

Rust workspace 共约 225,385 行。明显属于旧产品面的成员仍在默认 workspace：

- Command Center：约 69,076 行
- Shell：约 32,367 行
- Bridge protocol：约 7,147 行

三者合计约 108,590 行，接近 Rust 源码的一半。`Cargo.toml:2` 仍将其作为 workspace member。Mobian、mobile-smoke 和历史 Windows 脚本又形成更大的非产品表面。

处理方式：

- 给当前 Android Direct 产品设置最小 `default-members`；
- 将 Command Center/Shell/Bridge/Mobian/mobile-smoke 移入独立 legacy/compat workspace 或归档仓；
- `trillionnium-dbus` 不能直接删除，其中仍有生产 `AgentService`；先提取/重命名，再隔离真正 D-Bus 和 legacy feature。

### 超大单文件

- `apps/trillionnium-command-center/src/dashboard.rs`：约 40,450 行
- `apps/trillionnium-shell/src/main.rs`：约 31,968 行
- `apps/trillionniumd/src/android_agent_api.rs`：约 13,959 行
- `apps/trillionniumd/src/context_memory.rs`：约 12,418 行
- `crates/trillionnium-tool-runtime/src/supervised_codex.rs`：约 10,314 行

当前产品应优先拆：

- `android_agent_api.rs` -> `ui_gateway / invocation / context / egress / provider_turn / direct_result / recovery`
- `supervised_codex.rs` -> provider-neutral lifecycle/egress/process core + Codex adapter
- OpenClaw/Codex 重复 dispatch -> 一个 provider registry/trait

### 旧 feature 污染测试图

`legacy-plan-conformance` 与 `legacy-authority-effects` 仍通过 dev-dependency 进入 workspace feature unification。结果：

- `cargo test --workspace`：PASS
- `cargo test --workspace --all-targets`：FAIL
- 失败测试：`crates/trillionnium-tool-runtime/tests/production_direct_only.rs`
- 单独 `--no-default-features` 运行该测试：PASS

这说明 production-negative test 与 legacy conformance 共用 feature graph，测试拓扑自相矛盾。应把 legacy vectors 搬到独立 package/workspace，Direct 等价向量完成后删除 legacy feature。

### 手工镜像协议与重复状态机

Direct Tool protocol/socket/tool names/limits 被手工镜像到 Rust、JS、Python、Android config。建议从一个 machine-readable contract 生成 vocabulary/schema/golden vectors，同时保留不同 trust domain 的独立 parser/verifier。

System API replay、Accessibility replay、capability lease ledger、broker pending store、token registry、Rust operation journal 和 outer custody 共享大量机械实现。可合并：

- canonical JSON/digest helper
- bounded framing codec
- atomic write/fsync/rename helper
- ownership/link/SELinux path validation
- generation/fixture tooling

不可合并：

- 不同 trust domain 的 ledger
- Agent identity namespace
- egress consent 与 action lease
- System API 与 Accessibility policy/replay authority

### Source-only foundation 过度扩张

Capability lease 相关 Java 生产源码约 15,190 行，privilege broker/custody 等 inert foundation 约 14,896 行，但主 vertical slice 尚未接通。不要删除这些安全基础，也不要继续横向扩写；应冻结接口，只围绕一个真实 `open_uri` 或 semantic action 完成 end-to-end product activation。

### 仓库与产物卫生

- 本次 canonical control tree 有 36 个 dirty/untracked 条目；SDK 62、AiAuthority 6、vendor 13、SELinux 6，AiShell clean。
- 当前实现跨多个 dirty repo，没有 immutable cross-repo manifest，无法复现一个可信产品基线。
- canonical `target` 约 49 GiB；另有 stale checkout 的巨大 target、历史 evidence 和恢复副本。
- 不应直接删除整个 target：其中混有 package/TCB/evidence。先生成保留清单和 hash manifest，再清理明确可重建 cache。

## 8. 验证结果

已执行的针对性验证：

- `cargo fmt --check`：PASS
- `cargo clippy --workspace --all-targets -- -D warnings`：PASS
- `cargo test --workspace`：PASS
- `cargo test --workspace --all-targets`：FAIL，原因为 legacy feature unification 污染 production-negative test
- `cargo test -p trillionniumd --bin trillionniumd --quiet`：276 passed，2 ignored
- Direct Agent Host 新增定向验证：共享 Rust contract 45/45、generic UDS 9/9、两条 health 面 exact equality PASS
- vendor same-ABI host contract：11/11；OpenClaw product contract：PASS
- AiShell 从当前源码手工重编译的 DirectAgentResult/WorkflowRecoveryState/StrictAgentApiFrame JUnit：28/28；静态安全合同：PASS
- `cargo test -p trillionnium-tool-runtime --quiet`：124 个库测试与 1 个集成测试通过
- WindowsCompat all-variant absence contract：PASS
- Root Linux bootstrap crash/transaction test：PASS
- Rootfs no-mutation test：PASS
- OpenClaw product contract：PASS
- Agent direct product contract：PASS，但明确报告 effect integration 仍为 HOLD
- Agentd peer identity contract：PASS，但明确报告 artifact/device 仍为 HOLD
- Agentd production TCB test：FAIL；旧 archive daemon 的动态依赖闭包已漂移，只观察到 `libc.so.6`、`libm.so.6`

未执行/不能作为当前通过项：

- clean full Android product build：intentional daemon artifact gate 阻断
- current target-files/OTA/install：无合格产物
- physical device Direct conformance：runner 仍在 device I/O 前 HOLD
- 直接从 source tree 运行 payload extractor：缺少 Soong 打包后相邻的 toybox/zstd/verifier，不应当作产品失败或通过

## 9. 优先整改顺序

### P0：先让核心承诺成立

1. **SOURCE COMPLETE：** 已冻结跨仓 source manifest；它不替代 clean build、签名 artifact 或 release receipt。
2. **SOURCE COMPLETE：** 已冻结唯一 versioned Direct Agent Host ABI，让 Codex/OpenClaw 与两条 carrier 共享 lifecycle/result contract；active carrier 中继承的 Authority protocol/socket/fixture 命名已退役。历史 `plan` durable vocabulary 仍需单独迁移。
3. 完成一个真实 action lease vertical slice：broker/service registration、trusted pins、issuer、token delivery、consumer、journal、ACK、replay 和设备证明。
4. 激活 kernel custody 与 Direct outer custody；在此之前不开放 click/type/gesture。
5. 产出两次 clean、byte-identical AArch64 daemon build，刷新 rootfs/pins，通过 full product build。
6. 在物理设备上让 Codex/OpenClaw 各连续完成至少 30 次 `observe -> action -> verify`，覆盖 restart、response loss、replay、ENOSPC、power loss、rollback 和 privacy。

### P1：形成可维护产品面

7. 把 semantic OS tools 放在 Accessibility 之前：foreground/window、intent resolution、allowlisted settings、notifications、documents/media 等。
8. 从一个 machine contract 生成 Java/Rust/JS/Python vocabulary、limits、schemas 和 golden vectors。
9. 拆分 `android_agent_api.rs`、`supervised_codex.rs`，提取 provider-neutral core。
10. 将 legacy plan/Hepta/Mobian/Command Center/Shell/Bridge 从默认 workspace 移出；Direct vectors 完成后删除 legacy feature。
11. Windows 二选一：小型受监督产品服务，或移出 active tree。

### P2：仓库卫生

12. 建立 evidence/cache retention policy，先归档 hash-pinned TCB，再清理可重建 target 和恢复副本。
13. 将 superseded docs/mobile-smoke/packaging README 统一标记并移入历史归档，避免新开发继续引用旧架构。

## 10. 最终资格判断

Trillionnium OS 已经具备一套**方向正确且安全边界较扎实的 Direct Agent Native OS 架构**，Codex/OpenClaw 与 Root Linux 不是概念占位；它们已有真实源码和产品接线。

但截至本次审计，它还不能对外宣称“内置 Agent 已能通用、可靠地直接操控手机”，也不能宣称 Root Linux 已发布完成，更不能宣称 Windows 已适配。最准确的产品状态是：

> Direct Agent Native architecture PASS；low-risk source path PASS；general phone control HOLD；Root Linux release HOLD；Windows NOT IMPLEMENTED；device/OTA/release HOLD。
