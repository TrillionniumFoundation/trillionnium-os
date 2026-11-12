# v56 ordinary-Start Notes 验证准备

## 当前状态 — 2026-11-12，r3

**原始 collector/replay 闭包已取得 14 / 14 个完整文件并逐件验全 SHA。canonical v56 生产源已读取；已生成不可启动手机任务的未封装模板。实际 APK、签名 build receipt 和 fresh 设备身份仍待定，尚未运行 v56 手机测试。**

当前记录为 CURRENT-STATUS-r3.json、source-stage-v56-r1/SOURCE-STAGE-RESULT.json、v56-template-source-r2/ADAPTATION-RESULT.json、TEMPLATE-AUDIT-r2.json 和 RUNTIME-CONFIG-NEGATIVE-CONTROLS-r3.json。r3 只收紧离线 runtime schema 验证，已审 r2 手机模板字节不变。早期 BASELINE-CLOSURE.json 的 8 / 14、SOURCE-IDENTITY-PENDING.json 的公开 commit 为 null 都是历史记录，原字节保留；旧 README 原文保存于 README-early-checkpoint-r1.md。这些早期记录不能再用于描述当前状态。

本子线此阶段没有新增 H 调用、ADB 调用、手机写动作、锁获取或终端接管。六文件远程归档由 root 在获准的 H 窗口完成后交付，本子线核验全部本地归档字节。

## 确定身份与待定身份

| 项目 | 当前值或状态 |
|---|---|
| Repository | TrillionniumFoundation/trillionnium-os |
| canonical public commit | 5da3c83fe46edb2617934a92c06a10608accb68e |
| 本地冻结 commit | c2807a8093d064d2e158471788da9e98d4c4df94 |
| repository tree | e11aae799ecd27c7ccba0d1bfb65ee977c2e541e |
| component tree | 24e8d82d4befdab6f4f32ef7efeba7faad345a04 |
| canonical SOURCE-MANIFEST SHA | a0835cd66f81f3c4c770b92256742b90188b0664c6a274c29086bae03d1c39ec |
| version | 56 / 0.56.0-natural-web-responsive-observation |
| 实际 compiler source_commit | 等真实 build receipt；不能用树等价改写 receipt |
| 实际 APK / receipt / source inventory | 等最终原件及完整 SHA；不借用 v54 |
| 当前 UID / 主物理屏 ID | 等 root 正常取得协作锁后的 fresh preflight，不默认历史值 |
| 当前 runtime config / model | 等 fresh 原件及同一 candidate，不从历史任务继承 |

公开与本地冻结树等价由 root 直接验证。本子线独立保存并核验九个 canonical 生产源：PhoneObservation、BackgroundSession、BackgroundTaskTarget、BackgroundUiPreferences、MainActivity、TaskAuthorization、NotesOwnerIntent、LocalTaskController、HeptaAccessibilityService。精确长度和 SHA 在 adaptation result。

PhoneObservation.backgroundJson 实际仍是完整九字段 projection，bootstrap_source 固定 owner_selected_initial_app，不含 owner_task_selection。完整 OWNER selection 仍在 bootstrap / action / cleanup 独立核对；不会给原始帧合成缺失字段。主屏 context 也保持完整九字段，并由调用方提供两个强制独立参数。

canonical 通用 phone_acceptance 对 fixed tool 只认识八字段，实际生产源仍输出第九字段 owner_bound_execution_mode。因此适配保留原 pinned compatibility tools 和完整 source-aware extension，精确接纳第九字段及执行模式。没有把字段集合改成包含关系。生产源码使用独立 --controller-source 参数，不能把 compatibility tools 目录冒充生产源码。

## 当前产物

| 路径 | 用途 |
|---|---|
| ORIGINAL-SIX.tar.gz | root 交付的 45,890 字节完整归档，SHA 9cc92a87c9e1c0c64c77e0ef396d4d57b372b295f2130be4e26fcc36212b0f4b |
| retrieved-six-r1/INGEST-RESULT.json | 固定七个 tar member、manifest 和六个完整原件核验 |
| source-stage-v56-r1/originals/ | 14 个完整 collector/replay 原件；不要从这里启动历史 phone main |
| source-stage-v56-r1/reviewed-v54-replay/ | 三个精确 SHA 固定的既有 replay 派生验证器 |
| canonical-v56/ | canonical ref 实际生产源和通用 tools |
| seal_v56_notes.py | 单候选实际字节绑定生成器，正常模式必须有实际 APK / receipt / inventory / config |
| v56-template-source-r2/ | 不可启动手机任务的未封装源码；signed identity、UID、physical display、config 均未知 |
| v56-reviewed-plan-inputs-r1/ | 两个未来 narrow OWNER 指令，phone_tested=false，并非成功证据 |
| audit_v56_template.py / TEMPLATE-AUDIT-r2.json | 原件 / 模板哈希、完整函数变化枚举、旧谓词保留及拒绝路径检查 |
| semantic_scroll_gate.py | 额外语义位移必要条件，须结合原协议与实际业务结果复核 |
| CONTEXT-NEGATIVE-CONTROLS.json | 原始历史 context 的 19 个实质负例 |
| NEGATIVE-CONTROLS-r2.json | 真实旧 scrollbar 原图及严格输入的 14 个纯 host 负例 |

14 件是 collector/replay 闭包。普通 UI preparation 的外部 UI / R12 / r7 prerequisites 仍强制，未修改其 SHA 或 owner 协议，也未在此声称所有传递依赖已经本地重跑。UI SHA 为 b5483ad51dc3639a734d07169a7ad928f0ddf7ad2f5a46da4b3461abe8170c98；R12 SHA 为 d5a2caec2ad96b524d89651c0b4fbb63107678745dd4ccfa33368999fc0f817c。实际 prepare 须继续按原入口逐 pin 加载。

## 实际离线审查结果

TEMPLATE-AUDIT-r2.json 重新核验 14 个原件、三个 replay 派生源、16 个模板产物、九个 canonical 源和七个 diff。六个适配模块中，112 个函数体在只归一化 v54→v56 标签后完全相同，十个函数体在枚举的变更范围内，新增两个函数，删除零个函数。collector.execute、preparation.execute、main.perform 保持完整原逻辑，没有新增手机命令或改变任务时长。

- v6_app_binding 的 AST 仅版本标签不同，原 fixed field keyset 与 signed source context 完整保留。compatibility tools、v35_identity、live inflight、Moto Notes body helper 逐字节相同。
- warm_receipts.py 原 7,410 字节不变，继续核 request_sequence、首次 model hash、sdk_init_count=1、model_create_count=1、逐 request reset、完整 1..N 请求序列、唯一 run、同 PID / generation / UID、最终退出和 cleanup。typed tool children 不冒充新 native 生成。
- 完整九字段 observation/context 比较、OWNER selection、authorization SHA、callback_lease_current=true、callback_cancelled=false 的实际绑定保留。
- 原八个 main protocol check 表达式全部保留，只增加第九个非装饰正文像素门。像素变化不会自动变成语义滚动或连续交互结论。
- 模板 collector 拒绝旧 UID；模板 prepare 拒绝旧 APK；source context 拒绝未封装身份；正常 seal 拒绝缺实际 receipt / APK / inventory / runtime。四次拒绝都发生在任何传输、锁或输出目录创建之前。audit hook 观察到 subprocess / socket / lock 尝试为零。

本轮没有完整重跑历史 native/workflow collection，也没有 v56 手机正例。19 个 context 负例、14 个额外 host 负例、历史 9/9 scoped replay、8/8 main 子检查是不同范围，不能相加当成 v56 全量测试通过。

root 的独立复核指出离线 runtime binder 尚缺 schema / exact keyset 门，r3 已补齐：只接纳恰好 schema、model_profile、compute、context_tokens、threads 五个键，schema 必须为 hepta.local-runtime.v2。直接读取 canonical LocalRuntimeConfig.java（Git blob eace1ef538bb6b491ce7c13aeb26567829367477，SHA 81447620dbc2a789bba8c22d561c768144f4d5619859b202d07cd83660a05dce）也确认真实 threads 范围为 1..8，已将此前宽至 32 的候选门收紧。正常 seal 必经此 binder；16 个畸形配置负例全部拒绝。生产源兼容 legacy v1，但此资格 case 要求显式 model_profile 的 v2，不推定迁移，也没有合成实际 runtime 或手机成功证据。14 个原 helper 和 r2 模板源码未修改。

## 主屏滚动的真实门槛

历史 before PNG SHA 为 89ec9ce9e68ea59ecce3ac13dd93c1efe3c1721fb3b1e8f3fa5c97339cc5cded，after 为 64a9c5c2de0787ca9e8b118b7f5c47373434feb646ab108e5bea76c6955ae50f。两张原图均 1224×2992，差异 bbox [1212,2072,1224,2920]，只有 10,176 个滚动条像素。新第九门实际读取这些原字节，确认正文内部变化为 false 并拒绝；没有另拷或上传原图。

未来通过必须同时有：完整原图 SHA / 真实窗口 geometry；同 task / boot / generation / display 的命令及前后工作 fence；真实可滚动起点；root 查看实际原图记录至少三个不同完整列表锚点，其像素块有一致足够大的垂直位移；后续 Notes 实际结果与 cleanup。semantic_scroll_gate.py 对锚点位移采用保守精确像素匹配，不能用装饰像素或合成正例替代。

目前 effective_list_scroll_verified=false，continuous_interactivity_verified=false。历史 Notes 保存 / 列表 / 重开和 Settings 被采样显示的范围不变；旧 collector qualified=false 和旧机器判定原件不改写。

## 最终封装输入

只有 root 提供真实 signed receipt / APK 并完成当前设备 fresh UID / physical display / runtime preflight 后，才能另建最终 candidate。模板专用 release_sealed:false 字段不属于最终精确 V2 字段集合；最终字段不得为 null。实际 source_commit 取 receipt 的实际值，并独立保留 canonical public / local freeze 身份。

正常生成器所需参数：

```text
python -B seal_v56_notes.py
  --root <当前隔离准备目录>
  --candidate <全新实际候选 JSON>
  --candidate-sha256 <完整候选 SHA>
  --plan <实际审过且 hash 绑定的未来 case JSON>
  --production-source-root <canonical component 源目录>
  --build-receipt <实际签名 receipt 原字节>
  --apk <实际签名 APK 全文件>
  --source-inventory <实际 build inventory 原字节>
  --runtime-config <fresh 实际 config 原字节>
  --out <从未存在的新封装目录>
```

这是参数说明，不是当前可执行的手机命令。正常 seal 读取实际 APK 全文件，核对 SHA 和 receipt 长度；核原 signer、原 key、实际 compiler/source/count/unchanged 条件；核 inventory 原件 SHA、九个 canonical 生产源、runtime/model profile 的精确 hash。完整 inventory 成员再哈希由独立 build/source gate 执行，seal 不声称已替它完成。

同一 candidate 派生 source / APK / receipt / helper pins，prepare 与 collector 在任何手机动作前均核相同 UID、physical display、config SHA、plan SHA、candidate SHA。真实运行仍须原 installed APK 全哈希、正式服务、用户0、既有 su 授权、operation lock 和 owner handoff；生成器不授予这些权限。collector 仍留 qualified=false 给独立复核；生成器输出 phone_execution_ready=false，必须另有 root 控制的安装和普通 Start。

## 后续执行与未覆盖范围

1. root 正常核实当前 owner 关闭及 cleanup 已知，再按原协作锁流程取得设备。不能沿用已关闭 owner16，也不能仅因 flock 暂时可用就忽略 app/broker 状态。
2. 取得 fresh UID、physical display、runtime/model、正式服务状态，绑定实际 build receipt 和已哈希 APK；冻结最终 candidate，生成并复核封装，再完成同签名升级与安装全哈希 readback。
3. 对主屏共存 case，先在 task 开始前由 root 通过普通 Settings 界面准备真正可滚动的起点，并独立看实际原图确认；随后返回 Hepta 完成普通准备。不能假定再次 launch Settings 会重置列表位置，它可能恢复上次到底的状态。普通 prepare 作为正常 existing owner 子进程，核 PID / start ticks / boot、真实双应用 UI choice、原图、window dump 和 Start 坐标。它不点 Start、不创建 task、不操作 Notes；必须完成正常 owner handoff。
4. collector 使用原 operation lock、新 preparation 和 fresh 原屏幕执行普通 Start。未知结果不得自动重试创建备忘录。
5. 先做独立 background_only Notes 保存 / 唯一列表项 / 点击同条目 / 重开正文 / native session / cleanup 链，再做另一新 task 的 main_user_coexistence。两份未来 plan marker 已区分，旧 task/preparation/PNG 不能复用。
6. task 内主屏动作仍严格只有一次普通 Settings launch 和一次 swipe。task 前准备不替代实际 inflight before 截图：最终仍以该原图的真实可滚动边缘 / 裁切条目和前后三个相同完整条目的位移判定。主屏采样不在真实 inflight fence 内、缺可滚动起点或缺语义位移时保持未通过；不为等视觉审查延长 task，不增加 task 内输入，不改超时制造持续忙碌。

本适配只覆盖两个 Notes 模式，并非全量手机资格套件。包升级、拔线独立执行、冷启动、Stop/中断恢复、持久性、长时连续交互、机票和购物真实查询须各自实测；原 navigation suite 的两个 case 不能抵充。历史 cancel/recovery 计划名不证明存在可达 cancel runner，也不证明 Stop 已测。
