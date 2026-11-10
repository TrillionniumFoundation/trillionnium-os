# Hepta / razr 本地后台 Agent：实现、验证与当前阻断

日期：2026-11-10。本文区分本轮实测、此前保留的手机证据、官方发布资料和未验证候选。

## 当前交付状态

后台执行已写入 v36 候选，基于 v35 owner authorization，并移植原分支遗漏的 private-files identity 与 scoped catalogue 修复。实际通过构建的源码 commit 是 `1af05baf1e5313a0f5f7eb65107fb3bee305d65b`；对应草稿 [PR #137](https://github.com/TrillionniumFoundation/trillionnium-os/pull/137)。后续说明和待执行验收脚本不改变这个构建来源。

| 项目 | 本轮结果 |
|---|---|
| Pocket4 完整 JDK17 / Java 8 API release gate | 87 个检查记录全部通过 |
| 实际 BackgroundSession 客户端及 production 终结回归 | 45/45，通过；包含在完整 host gate 中 |
| 实际 BrokerProtocol 协议回归 | 43/43，通过；包含在完整 host gate 中 |
| Android SDK34、DEX 与 NDK 编译 | 通过，绑定 167 个实际 compiler inputs |
| 待执行真机驱动的进程身份解析回归 | 22/22 合成样例通过，并经独立复审；未运行驱动入口或手机 |
| Mac 编译产物传到 Pocket4 | 已确认完整提交，355230 bytes，完整 SHA 一致 |
| APK 打包及现有证书签名 | 请求已提交，但调用超时；最终执行状态未知 |
| v36 安装到手机 | 未提交安装命令 |
| v36 本地模型后台真机测试 | 未执行，不计任何通过项 |
| 购物、机票、中文备忘录端到端验收 | 未执行 |

初版 Android 编译暴露 `Os.unlink` 不在 public SDK 中；r2 使用 API21 起提供的 `Os.remove`。另修复未知后台清理被后续 scope/Stop 分类覆盖的问题：只要清理仍未知，最终状态保留 blocked。两个真实 production 终结回归对 r1 失败、对 r2 通过。初版失败记录没有改成通过。

## 当前外部阻断

在打包阶段，HeptaRuntime 连接从 MCP 超时进一步变为明确的 `tunnel_client_not_connected`。连不访问手机的 host list 与 Mac health 都返回同一 tunnel-client 错误。原打包请求已使用同一 idempotency key 尝试核对，但连接不可用，不能断言它没有启动或已完成。

恢复时必须先核对这一个既有打包请求及 `assembly-r1/RESULT.json`，不能另用新 key 重跑。若存在签名 APK，还须完成实际 SHA、证书、内嵌 build identity 和静态报告核验，再安排安装。

发布前最后一次 host-list 复查仍失败，错误进一步变为 `tunnel_client_not_seen`，消息为 tunnel-client 已超过 300 秒未出现。连接没有恢复，手机状态也没有新的读回。

## 手机现场与并行会话

本轮最后确认的已安装版本是 v34。已读 runtime 配置为 Nanbeige4.2-3B Q4_K_M / NPU / 4096 context / 4 threads。

14:37 UTC 的读取显示正式 Hepta AccessibilityService 未启用，只有测试 probe 与系统服务。14:57:59 UTC 的新读取已经包含正式 Hepta 服务，因此不能把早先的临时状态当作当前永久原因。

设备的合作操作锁仍由另一个存活 operator 持有。本轮没有杀掉该进程、替换锁、发送其 close 请求或改写它的测试记录。旧 owner 在 14:42、14:45、14:47 UTC 又完成了观察、显式恢复和 scope-remove 阶段，不能把它当作失效锁。

scope 存在一个尚未解决的时间点差异：旧 helper 的 14:47 回执记录精确 hash 守卫的移除，并两次读取 scope 不存在；本轮 14:57:59 的独立 `run-as ... cat files/qualification-scope.json` 则返回 enabled 的 `c426-nano-v34-lifecycle-r3`。没有证据确定后续写入者、缓存或连接差异。恢复连接后需要重新对账当前文件、实际 ADB 连接、idle 状态和锁归属，不能直接重复原操作或把旧测试报告改写成成功。

## v36 后台实现

模型继续以普通 APK UID 使用手机本地 GGUF 和已固定的 GenieX/llama.cpp runtime；broker 来自同一安装 APK，使用现有正常 su 授权机制启动。本实现不修改 Magisk policy，不新增 Internet permission、任意 shell tool 或 exported action receiver。

用户在 Hepta 中选择后台模式、本次允许的 1–6 个应用和起始应用。起始打开动作是 owner bootstrap，明确记录 `bootstrap_model_issued=false`，不冒充模型工具调用。后续观察、模型决策和工具执行继续使用既有 controller 和授权检查。

broker 只提供 create/state/launch/back/close。其 socket 核对实际 peer UID、task generation、deadline 和固定 package allowlist。副屏请求 trusted、own focus、disabled top-focus stealing，并读回 flags 与 IME hide；不请求 secure 或 always-unlocked。

Accessibility 根、截图与节点动作绑定同一 display 和 generation；节点派发前再次检查实际 window、package 和新鲜度。Back 另绑定预期顶层包与目标 UID。后台 HOME 和坐标手势当前拒绝，失败不会自动转向 display 0。

启动前写入持久 lease；停止、锁屏、超时和退出均走清理。已启动 broker 的正常关闭路径要求 broker 确认 RELEASED 且 app 实际观察到显示器消失，才删除本代 journal。恢复流程另允许在确认 boot count 变化，或绝对 expiry 加 2 秒已过且阻止晚到 create 后，独立确认对应 display ID/name 均消失再清理；未启动 broker 的路径也可清理。TTL 经过本身不是释放证明。响应未知、Binder 卡住、删除失败均保留阻塞；恢复入口只清理旧租约，不恢复或重放任务。

能力边界：已有主屏/其他屏幕 task 的目标应用会被拒绝；第三方应用主动启动其他 Activity、权限页、支付页，或用户同时打开同一个 app，仍需真实手机验证。UI 自绘内容、缺少 Accessibility 节点的界面尚不能据此声称支持。副屏也不隔离共享 RAM、热预算、通知、音频或 app 数据。

Android 官方 Computer Control 同样采用受控后台虚拟屏幕，但要求 OEM 预装助手、特权权限及目标 app 的系统授权。普通侧载 Hepta 不能直接按普通 SDK 功能使用这条路径。[官方说明](https://developer.android.com/ai/computer-control)

## 模型选型与已准备配置

本轮尚未产生一个通过 v36 手机验收的“最佳模型”。针对实际工具链，下一轮首测候选为 **Orvena-4B Q4_K_M / NPU / 8192 context / 4 threads**；Nanbeige4.2-3B / NPU / 4096 作为中文对照。候选配置文件不会自行激活，也没有写到手机。

| 模型 | 检索与现有证据 | 决策 |
|---|---|---|
| Orvena-4B | 2026-11-05 发布，针对手机工具任务；官方 547 个模拟 iPhone 任务通过 440 个。手机上已有 2.783 GB Q4_K_M artifact | 优先同 APK 验收；官方成绩不能当 Android 成绩 |
| Nanbeige4.2-3B | 中文/英文与多轮工具能力；本机 NPU 证据明确，但保留任务存在重复 wait 和错误继续行动 | 保留中文对照，不因已有 NPU offload 就称已可用 |
| LFM3-1.7B | 2026-10-27 新发布，约 1 GB 四位量化，定位可专门化的端侧小模型 | 可作为低延迟专门任务候选；不代替复杂多步任务验收 |
| MiniCPM5-2B | 提供 GGUF、LiteRT、DSpark 等端侧格式 | 可测试新的专用 runtime；旧版失败结果不合并为新后台版本成绩 |
| LFM2.5-8B-A1B | MoE，手机已有约 4.845 GB Q4_0 artifact | 较小 MoE 的第一阶段实验；此前 abort 的单 token probe 不计吞吐 |

一手来源：[Orvena 发布与评测](https://orvena.app/blog/orvena-4b-on-device-model/)、[Nanbeige 模型卡](https://huggingface.co/Nanbeige/Nanbeige4.2-3B)、[LFM3 发布](https://www.liquid.ai/blog/lfm3)、[MiniCPM5 模型卡](https://huggingface.co/openbmb/MiniCPM5-2B)、[LFM2.5 MoE 模型卡](https://huggingface.co/LiquidAI/LFM2.5-8B-A1B)。

Orvena 历史普通任务的三个请求约 19.27 / 14.53 / 15.70 秒，动作 open → click → done；结果仍标记 `goal_independently_verified=false`。其旧 core9 的 6/9 也不构成 v36 后台通过。不同 APK、context、采样和热状态的结果不能混成统一排名。

## Hexagon：实际证据与性能瓶颈

本机确认是 SM8750 / Snapdragon 8 Elite。Qualcomm 公布该代 Hexagon 包含 scalar、HVX/vector、tensor 加速器及 INT4/INT8/INT16/FP16 支持。新一代芯片的额外能力需要单独区分，不能替代对本机 v79 的检查。[8 Elite 官方规格](https://www.qualcomm.com/smartphones/products/8-series/snapdragon-8-elite-mobile-platform)

保留的普通 Hepta 任务 stderr（并非只有 standalone probe）记录：HTP0、v79、45/45 层 offload，NPU model buffer 2492.31 MiB、KV 704 MiB、compute 831.03 MiB；另有 CPU buffer。硬件查询为 6 HVX、1 HMX、8 MiB VTCM。它证明 NPU tensor offload，不能扩大为每个算子、tokenize 或采样都在 NPU。各缓冲区统计也不能简单相加当作进程实际峰值 RSS。

Nanbeige 保留失败任务的关键数据：

| 步骤 | Prompt tokens | Prefill 秒 | Decode 秒 | 请求总秒 |
|---|---:|---:|---:|---:|
| 1 | 2260 | 10.12 | 11.95 | 27.44 |
| 2 | 2870 | 13.41 | 19.60 | 33.06 |
| 3 | 3075 | 14.77 | 21.31 | 36.14 |
| 4 | 3196 | 17.29 | 28.94 | 46.28 |
| 5 | 3313 | 18.16 | 30.39 | 48.60 |
| 6 | 3434 | 18.65 | 36.37 | 55.08，deadline |

六轮同一 worker，只创建一次模型；每轮 reset 后 prefix match 为零，仍完整 prefill。没有 context overflow 证据，也没有足够温度/频率数据证明热降频。更重要的是第 2 步已经到达页面，之后重复 wait，第 6 步反而尝试进入更深页面；单纯加长 timeout 不能修复任务正确性。

保持现有稳定 GenieX 0.10.0 和固定 llama commit。官方当前还有 0.10.1 预发布；KV/prefix 与 MTP 修复值得后续独立评测，不在后台通路改造时同时替换整套 runtime。[GenieX releases](https://github.com/qualcomm/GenieX/releases)

当前 llama.cpp Hexagon 后端已支持 K-quants。HTP 32-bit 映射约束与按会话动态映射是 runtime 工程问题，不等于整机只有该数量 RAM，也不表示 HTP0+HTP1 是两块物理 NPU。[上游开发文档](https://github.com/ggml-org/llama.cpp/blob/master/docs/backend/snapdragon/developer.md)

后续性能改动优先单独实验紧凑 JSON 与不丢权限语义的 prompt 投影；短 reason 和终止提示需要质量对照；不能直接删 reset 冒充正确 KV 复用。实际 tokenizer 已自动加入 Nanbeige BOS，没有依据再添加一个首 token。

## 更大 MoE 的可行性

[MobiInfer-Android](https://github.com/IPADS-SAI/Mobiinfer-Android) 已提供专家从闪存按需加载、LES 预取和 DSpark 的手机实现，公开支持 30B–35B 级 MoE。其 MiniCPM-V 4.7 包约 19.3 GB，Qwen3.5-35B 包约 25.1 GB。作者在 OnePlus 13 / 8 Elite、512-token prompt、128-token output 的配置报告约 13.65 token/s decode；这不是本台 razr 的实测。

因此“大 MoE 在手机上运行”有工程路径，但“3B active”不表示只需 3B 权重存储。必须另测闪存读取、峰值 RAM、专家缓存、长上下文、持续温度和主屏并用，并确认量化、专家 top-k 和投机采样没有改变所声称的质量边界。本轮未下载或安装这组大模型，也未报告它通过 Hepta 工具任务。

## 恢复连接后的验收顺序

1. 核对打包请求的唯一执行结果及现有签名；不重复未知写操作。
2. 对账旧 owner、当前 scope、应用/模型 idle 与 Accessibility binding，完成正常操作窗口交接。
3. 保留已装版本与配置证据，按同证书升级 v36，再确认普通 UID、原有模型与无外部模型路径。
4. 先通过现有 Hepta UI 发起后台计算器；目标结果必须来自真实结果控件及模型动作前后转变，不能只信 `done`。同时记录副屏、主屏 focus、普通 UID native PID 和实际 NPU offload。
5. 运行 Stop、锁屏、超时、IPC/进程退出、旧 journal 恢复和同应用主屏冲突测试。检查实际 display 消失，不把进程 kill 当释放。
6. 同 APK 对照 Orvena 与 Nanbeige，再执行完整既有任务集、中文备忘录保存/重新打开、携程航班搜索及购物搜索/结算前流程。交易完成需要用户具体订单内容与授权；这里不创建虚构订单。
7. 增加主屏真实交互并发测试；静态 focus 采样通过不等于主屏同时输入通过。发布成功率、错误动作、任务总时延、内存与清理结果，保留失败。

本文不把历史 shell 虚拟屏幕演示、host fixtures、编译或 token benchmark 当作新版本端到端手机通过。
