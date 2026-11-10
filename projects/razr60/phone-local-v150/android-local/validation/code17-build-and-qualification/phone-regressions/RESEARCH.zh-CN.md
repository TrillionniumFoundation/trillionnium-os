# Hepta / razr 本地模型与 Hexagon 技术核查

研究日期：2026-11-09。本文是项目技术记录；手机验收结果另见对应版本的脱敏结果，不以研究或构建通过代替真机通过。

## 结论与选择原则

目标是手机里的本地模型根据原始用户指令选择工具，Hepta 在手机上校验并执行，操作后重新观察。模型大小、官方榜单和单次 token/s 都不能单独决定可用性。优先比较相同 APK、相同原始任务、相同动作与终态判定下的完成率，然后比较总时延、内存余量和持续温度。

已完成的同版 Code16 / NPU / 4096 基础九项测试：Nemotron 3.5 Bolt E4B 为 **6 pass、3 fail**，Gemma 4 E4B QAT Q4_0 为 **7 pass、2 fail**。两次测试的 APK、原始九项任务、驱动和断言一致，只有模型配置不同；初始画面和热状态没有完全控制，不能外推成通用排行榜。两者都不能宣布任意 App 自动操作已完成。

Code17 保留当前可编辑字段的实际值、view_id、位置和状态，并区分非交互可见文字与当前输入。其四项针对性实测中，Gemma 为 **2/4**，LFM3 / NPU / 8192 为 **0/4**。随后发现 Code17 的确定程序缺陷：长动作历史挤占 prompt，预算裁剪先删除当前按钮，后删除旧派发序列。真实计算器轨迹里的数字“1”、乘号和等号曾因此从模型可选节点及 GBNF 中消失。不能把这类失败全部归咎于模型。

Code18 已实现这项通用修复：压缩实际历史中重复的包名、明确记录省略、优先保留当前可操作目标，并让可打开应用列表与实际语法一致。没有写入计算题答案、应用专用完成器或按 reason 偷改原始模型动作。其 LFM3 / NPU8192 四项真机复测仍为 **0/4**，全部任务清理已知、网络恢复经两次读回确认。计算器关键帧中的 25 个节点完整保留，但模型仍选择错误动作或反复操作；find_app 的只读历史又暴露了独立 1024 字节历史上限造成的来源遗漏，因此该项不能简单归为纯模型失败。

Code19 将稳定画面的内部等待上限从 2 秒对齐到原请求的最多 10 秒绝对期限；仍保持原任务期限、观察新鲜度、动作归属和取消保护。其源代码、APK 和完整 CI 已验证，手机已安装同签名版本并保留 Gemma / NPU4096 配置。另一个可见控制流程使用相同冻结计划启动了九项测试，但主机连接中断使原套件留下 **1 pass、1 unknown、7 not_run**。恢复记录与手机日志表明第二项随后自然结束、清理已知，网络设置经两次读回恢复；这不能回填成完整九项通过。普通 Start、后台持续工作、Stop 和重启后新任务仍待独立验收。

## 本机硬件与 NPU 路径

真机系统报告是 SM8750、Snapdragon 8 Elite、Hexagon HTP v79、Adreno 830、Android 16。不是 8 Elite Gen 5 的 SM8850 / v81。系统 MemTotal 约 14.82 GiB，空闲可用内存通常约 8.8–9 GiB；这不等于模型可长期独占的额度。

高通产品资料披露 Hexagon 的标量、向量、张量处理能力及 INT4 / INT8 / INT16 / FP16 支持，称相对上一代 NPU 性能及每瓦性能提升 45%。该 brief 没有提供足以引用的绝对 TOPS 数字；不能给本机编造 75 或 80 TOPS。实际 token 延迟还受权重读取、算子支持、量化布局、KV cache 和系统竞争影响。[高通产品 brief](https://www.qualcomm.com/content/dam/qcomm-martech/dm-assets/documents/Snapdragon-8-Elite-Platform-Product-Brief.pdf)

当前可用主路径是 GenieX 0.10.0 的 llama.cpp / GGML Hexagon 后端，另有 Adreno OpenCL 和 CPU。QAIRT 路径使用对应芯片的预编译模型包，不能把任意 GGUF 当作 QAIRT context binary。官方建议 GGUF 优先使用 Q4_0 取得较好的 Hexagon 支持；现有 Bolt 的 Q4_K_M 能卸载并不意味着与 Q4_0 有同等内存和内核效率。[GenieX README](https://github.com/qualcomm/GenieX/blob/main/README.md) · [Android API](https://geniex.aihub.qualcomm.com/en/run/android/api-reference)

llama.cpp 日志里的 “offloaded … layers to GPU” 是通用设备抽象，Hexagon 也可能打印这句话。应结合 HTP0、v79 库和实际设备配置认定执行后端。当前 Code16 Bolt 的 58 次 native 调用均有正向 HTP0 / 43 层卸载证据；这不证明每个算子均在 NPU，更不等于测到了 NPU 利用率。[llama.cpp Snapdragon backend](https://github.com/ggml-org/llama.cpp/blob/master/docs/backend/snapdragon/README.md)

对当前固定 GenieX 0.10.0 所依赖的 llama.cpp commit `19cce6919992fdffd92e0ac152caaf1e2b8f254e`，源码默认 `HTP_OP_MAX_VMEM_DEFAULT=3,355,443,200` 字节，即 3200 MiB / 3.125 GiB。这是软件的单会话映射预算，并非测得的整机内存或芯片全部地址能力。`prep_op_bufs` 会复用当前批的映射、释放当批不用的映射，并在失败时重新整理 32 位映射。因此不能仅用整个模型文件大于该窗口就判定无法运行；仍须验证单批张量与计算缓冲能否映射、重排峰值和实际速度。这种映射复用也不等于按激活专家从 UFS 流式加载。[固定 htp-ops.h](https://github.com/ggml-org/llama.cpp/blob/19cce6919992fdffd92e0ac152caaf1e2b8f254e/ggml/src/ggml-hexagon/htp/htp-ops.h) · [固定映射实现](https://github.com/ggml-org/llama.cpp/blob/19cce6919992fdffd92e0ac152caaf1e2b8f254e/ggml/src/ggml-hexagon/htp/main.c)

同一 GenieX 0.10.0 的 Android plugin 默认暴露两个虚拟 HTP 设备，但 `npu` 别名只选择 HTP0；显式 `HTP0,HTP1` 设备列表有公共接口支持。虚拟会话共享同一块物理 NPU，不增加物理 RAM，也不代表现有 Hepta 已同时使用两个会话。大模型能建立 context，不保证 Android 和目标 App 仍有足够工作内存。[固定 plugin](https://github.com/qualcomm/GenieX/blob/v0.10.0/sdk/plugins/llama_cpp/src/plugin.cpp) · [设备解析](https://github.com/qualcomm/GenieX/blob/v0.10.0/sdk/src/device.cpp)

当前 native worker 明确请求 `n_gpu_layers=-1`、本地配置的 CPU 辅助线程数，以及 `GENIEX_POWER_MODE_SUSTAINED_HIGH_PERFORMANCE`。这是 SDK 配置请求，不是实测最高频率或利用率；未通过修改系统温控来追求短时数字。

可用的厂商参照是 Qualcomm AI Hub v0.66.0 的 LFM3-1.7B / Q4_0 / GenieX v0.10.0 数据。在 Galaxy S25 / 4096 context 下，CPU、Adreno GPU、Hexagon NPU 的 prefill 分别约 211.55、454.40、2314.70 token/s，而 decode 约 35.96、36.06、35.95 token/s。该表说明 NPU 的 prefill 优势可能远大于 decode 优势；不能把矩阵计算能力或 prefill 倍数直接换成完整 agent 的速度。这里是发布者测量，并非本机的成绩；本机任务上下文、严格动作语法、输入长度和运行条件不同。[官方 perf.yaml](https://github.com/qualcomm/ai-hub-models/blob/v0.66.0/src/qai_hub_models/models/lfm3_1_7b/perf.yaml)


## 候选模型与适用边界

| 候选 | 公开定位 | 本项目判断 |
|---|---|---|
| LFM3-1.7B | 2026-10-27 发布，文本、中文与工具调用；官方 4 bit 约 1 GB | Code17 NPU8192 实测较快，但针对四项 0/4；当前不能选作最终可靠操作模型 |
| Nemotron 3.5 Bolt E4B | 2026-10-23 发布，基于 Gemma 4 的工具与推理后训练 | 当前已完成 6/9 的候选；实际本机 GGUF 6.18 GB，不能按名字理解成 4 GB |
| Gemma 4 E4B QAT Q4_0 | 文本与多模态家族，E4B 有有效参数口径 | Code16 同协议 7/9；Code17 针对四项 2/4，长轨迹暴露预算缺陷；当前文本 GGUF 不包含完整视觉链路 |
| Spark X2.6-4B | 2026-10-21 发布，中文/英文及 thinking 配置 | 需要其真实模板与 parser；旧版本失败不能证明新代码下必败 |
| MiniCPM5-2B | 2026-09 发布，文本工具调用 | 参数小仍不保证当前 harness 的操作成功率 |
| MobiMind1.5-2B-W8A8-0717 | 专为移动 GUI，MobiAgent / MobiInfer / QNN 路径 | 手机诊断推理可运行；当前尚未构成归属完整的实时视觉控制循环 |
| UI-Venus-2-9B | GUI 定向模型，基于 Qwen3.5，覆盖中英文 App | 更贴近任务，但显著增大内存/时延；动作格式和视觉坐标需要适配 |

LFM3 的官方 BFCL、ToolSandbox 等分数是发布者指定框架和精度下的结果，不能写成该 razr 的 Q4_0 成绩。其工具调用格式已由 LFM2 风格变为 qwen3_coder 风格 XML；不能只换文件名而继续套旧 parser。当前 Hepta 的严格 JSON 动作方式与原生工具模板是不同实验配置，需要独立比较。[LFM3 发布](https://www.liquid.ai/blog/lfm3) · [LFM3 模型卡](https://huggingface.co/LiquidAI/LFM3-1.7B)

官方资料：
[Nemotron 模型](https://huggingface.co/nvidia/NVIDIA-Nemotron-3.5-Bolt-E4B-4GB)；
[Gemma E4B QAT GGUF](https://huggingface.co/google/gemma-4-E4B-it-qat-q4_0-gguf)；
[MiniCPM5-2B](https://openbmb.cn/docs/en/guides/minicpm-text/minicpm5-2b)；
[Spark X2.6 FAQ](https://github.com/XHToken/Spark-X2.6/blob/X2.6/FAQ.md)；
[MobiAgent](https://github.com/IPADS-SAI/MobiAgent)；
[MobiAgent 手机运行说明](https://github.com/IPADS-SAI/MobiAgent/blob/main/phone_runner/README.md)；
[UI-Venus-2-9B](https://huggingface.co/inclusionAI/UI-Venus-2-9B)。

LFM3-VL-2B 同期发布，约 1.92B 总参数，具有图片/视频输入；官方建议 llama.cpp b11960 或更高版本及匹配的 mmproj。它适合读 App 画面，但官方也明确不推荐复杂推理和多轮对话，不能凭视觉支持就假定它是最可靠的整机 agent。[LFM3-VL 模型卡](https://huggingface.co/LiquidAI/LFM3-VL-2B)

d1-2B 可用一次 forward 回答候选选择、定位、抽取等带类型问题，不生成长文本。它可能适合以后做观察校验或有限候选选择；仍需手机运行支持和任务数据校准。官方 5.7 ms 是 H100 测量，不是手机成绩；它也不是直接替换通用多步规划器的聊天模型。[d1-2B 模型卡](https://huggingface.co/LiquidAI/d1-2B)

## Code16 Bolt 实测性能与改进方向

57 次正常完成调用的中位数：

| 指标 | 数值 |
|---|---:|
| native 整体耗时 | 34.755 s |
| 完整权重 SHA 校验 | 6.907 s |
| 模型 create / 加载 | 8.511 s |
| generate | 18.239 s |
| SDK TTFT | 5.649 s |
| decode | 8.478 token/s |
| prefill | 344.32 token/s |

另一次调用在计算器任务期限到达后取消，未被填成零值或加入完整调用分布。SDK TTFT 从生成阶段计算，不包括前置校验与加载，也不是点击 Start 后的实际等待时间。

57 次正常调用共读完整 6,180,446,208 字节模型做身份校验。hash + create 合计 899.610 秒，占这些 native 总时间的 44.79%。下一步应研究同一任务内复用已加载模型：保留模型身份与配置，逐步绑定新的 prompt / grammar / observation，任务结束和取消后可靠释放。不能只删除校验或延长任务期限来掩盖开销；持久进程必须重新验证取消、崩溃、请求归属和模型切换。

实测 129 个资源采样点覆盖第 3 项中途至结束，不含前两项。当前 HAL 报告的 CPU / GPU / NSP 峰值分别为 65.7 / 58.8 / 62.6°C，skin 41.960°C，电池 31°C。全系统 MemAvailable 最低约 0.845 GiB。不能把全系统余量写成模型 RSS，不能从 skin status 单独断言具体降频，未测电能、功耗或利用率。

LFM3 在 Code17 的保守 UTF-8 上界预算下，4K 上下文只给整个任务 prompt 留约 301 字节，实际无法承载必要的屏幕数据。因此已准备比较的是 NPU / 8192 / 4 线程；这保留原保护而不放宽预算。新安装的默认值与最终所选模型应在发布前对齐，不能把不足的 4K 默认标成可用。

## Code17 两种配置的保留证据复算

两轮使用相同 Code17 APK、原始四项任务、core 驱动和断言。Gemma 为 NPU4096，LFM3 为 NPU8192；由于上下文、生成动作及初始状态不同，这是实用配置比较，不是同 prompt 的纯速度基准。下表来自原始 action / observation / native receipt 的独立重算，原始失败记录均保留。

| 指标 | Gemma 4 E4B QAT Q4_0 | LFM3-1.7B QAD Q4_0 |
|---|---:|---:|
| 针对四项通过数 | 2/4 | 0/4 |
| native 调用 / 正常完成调用 | 40 / 39 | 11 / 11 |
| 有正向 HTP0 卸载证据的调用 | 40 | 11 |
| 观测到的卸载层数 | 43 | 25 |
| 完整 native 调用中位耗时 | 28.651 s | 9.417 s |
| App 记录的模型调用中位耗时 | 28.804 s | 10.033 s |
| SDK TTFT 中位数 | 5.625 s | 1.903 s |
| decode 中位数 | 9.643 token/s | 27.790 token/s |
| prefill 中位数 | 346.373 token/s | 963.584 token/s |
| hash + create 占完整 native 总时间 | 42.65% | 23.16% |

Gemma 的另一调用发生任务截止取消，未计入正常完成速度分布。LFM3 的所有 native 调用完成不等于任务成功：至少一次原始输出在文字理由中描述继续计算，实际工具却打开不相关 App；代码没有把这条错误选择修正成正确动作。该现象和预算丢节点是分别记录的缺陷。

两组独立资源监测都在测试前启动，并持续到套件结束；15 秒采样的当前 HAL 数据覆盖整个时段。Gemma 89 个采样点中 85 个位于套件窗口，LFM3 18 个中 12 个位于套件窗口。下列温度仅取 `Current temperatures from HAL` 段，未把历史 cached 温度或电压、电流指标混入摄氏温度。

| 套件内采样值 | Gemma | LFM3 |
|---|---:|---:|
| CPU 最高温度 | 66.1°C | 53.4°C |
| GPU 最高温度 | 58.8°C | 47.3°C |
| NSP 最高温度 | 60.3°C | 52.3°C |
| skin 最高温度 / 最大 sensor status | 41.051°C / 3 | 34.144°C / 0 |
| battery 最高温度 | 30°C | 25°C |
| 全系统 MemAvailable 最低值 | 2,031,232 KiB | 6,714,836 KiB |

LFM3 任务较短且失败路径不同，不能用上表推出同等工作量的耗电或热效率结论。同 UID RSS 也有保留，但映射共享页面可能重复计算，且不涵盖完整 NPU 分配；不拿它替代模型总运行内存。没有功率、电能或 NPU 利用率测量。

两轮均关闭 Wi-Fi 与当前数据订阅，结束后两次确认网络设置及原默认连接恢复。原始断言重算一致，全部 case 的清理已知；两轮都还是 private-debug 入口，不能推断普通 Start、Stop、重启或锁屏场景已经通过。

脱敏复算来源：[Gemma 摘要](GEMMA-SANITIZED-SUMMARY.json)、[LFM3 摘要](LFM3-SANITIZED-SUMMARY.json)、[同协议比较](COMPARISON.json)。各摘要包含原统计文件及原计划的 SHA256。

## 更大的 MoE：能做，但必须分清计算、RAM 和存储

MoE 的活跃参数决定每 token 主要计算量，**总参数仍决定需要保存的权重池**。以全部参数平均 4 bit 的理想下界计算：

| 规模 | 纯权重理想下界，十进制 GB | 不包括 |
|---|---:|---|
| 8.3B | 4.15 | 量化 scales、混合精度、KV、运行时及 App |
| 24B | 12.0 | 同上 |
| 35B | 17.5 | 同上、视觉编码器与投影可能另计 |

这只是算术下界，不是具体 GGUF 文件大小或运行内存保证。当前手机约 13 GB 剩余存储，直接部署完整 35B 4 bit 权重已不满足这一存储条件。按需载入专家可减少工作 RAM，不会让权重池从磁盘消失。

**优先评估 8B 级 MoE。** LFM2.5-8B-A1B 为约 8.3B 总参数 / 1.5B 活跃，2026-05-28 发布；比 24B 或 35B 更接近本机可操作范围。官方 Q4_0 GGUF 的 LFS pointer 指定 4,844,678,368 字节，SHA256 `48ed1465d761311b2fd57b7fb46cf969a20b3a8281945b04e10f52bd1609e715`。这里核验的是官方 pointer 与固定后端源码，没有下载并验证本机模型文件，更没有完成该 MoE 的手机推理。[官方模型卡](https://huggingface.co/LiquidAI/LFM2.5-8B-A1B) · [官方文件 pointer](https://huggingface.co/LiquidAI/LFM2.5-8B-A1B-GGUF/raw/main/LFM2.5-8B-A1B-Q4_0.gguf) · [发布说明](https://www.liquid.ai/blog/lfm2-5-8b-a1b)

该模型默认采用 reasoning，并支持工具调用；现有 Hepta 的固定 profile / 模型 SHA 入口不能直接接受这个未知模型。固定依赖中存在 `lfm2moe` 加载器与相关 Hexagon 算子实现，只能证明有进一步验证的源码基础。实际还须核验张量布局、专家路由、量化、模型加载峰值、严格输出协议及整套工具任务。不能用 A1B 推断内存只需 1B，也不能把源码中出现算子名称写成已跑通。

**24B 级。** LFM2.5-24B-A2B 的总权重下界已接近 12 GB，实际还需缓存与系统余量。其 reasoning 行为也会改变动作生成耗时，不能把它当作更大但同速的替换文件。[官方模型卡](https://huggingface.co/LiquidAI/LFM2.5-24B-A2B)

**LES / MiniCPM-V-4.7-35B-A3B。** 官方实现用层级专家预取、流式读权重和量化等降低常驻 RAM。约 3 GB 工作 RAM 与 13+ token/s 的宣传测量在 iPhone 17 Pro Max；该数字不是权重文件大小，也不是 8 Elite 的 NPU 性能。它值得进一步移植研究，但不能作为当前 Hepta 已可用的证明。[官方模型卡](https://huggingface.co/openbmb/MiniCPM-V-4.7-35B-A3B) · [官方运行实现](https://github.com/OpenBMB/llama.cpp-omni)

**EStream。** 2026-09 的论文把专家池放在 UFS，以有限的 NPU 可寻址区域分批映射，动态路由用复用专家图处理。其强项是 prefill-only；测试手机为新一代 SM8850 / v81。不能把其 prefill 加速倍数直接当作本机持续解码或完整工具任务加速。[论文摘要](https://arxiv.org/abs/2609.06551) · [论文全文](https://arxiv.org/html/2609.06551v1)

大 MoE 的后续准入条件应包括：实际可用磁盘与内存、原生算子支持、持续 decode 而不仅 prefill、首任务与后续动作时延、取消后已知清理，以及同一套手机工具任务的成功率。未进行过的模型只能列为候选，不标注“已配置成功”。

## 无外部模型与验收边界

Code16 Bolt 测试期间关闭了 Wi-Fi 和当前数据订阅，148 个运行期/结束期采样均无默认网络，测试后两次读回确认原设置恢复；该 APK 未声明 INTERNET。网络采样不是包捕获，也不构成任意瞬间整机所有链路均不存在的证明。

验收同时保留：原用户指令、不可复用的 task/run 身份、手机 native 进程、模型原始输出、观察绑定、真正派发动作和最终 UI。Host 通过 ADB 启动与收集测试，不预先给手机注入正确动作或答案。普通 Start 按钮、实际后台运行、Stop、空闲重启后的新任务要另行验证，不能从 debug 任务通过推断它们通过。

“后台”应明确为 Hepta Activity 离开前台、服务继续根据屏幕观察工作；不能未经测试宣称锁屏、合盖、灭屏、所有厂商省电策略或所有 App 均可操作。尚未接入实时视觉模型的版本也不能宣称可稳定控制没有可访问节点的自绘界面。
