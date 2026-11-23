# Hepta 本地模型与 Snapdragon 8 Elite NPU：选择依据与工程边界

**资料复核日期：2026-11-16。** 本文沿用本轮已保存的手机证据，不新增手机操作或测试。任务统计锁定到 E1 的 5dfa 版本报告：21 个实际任务中，8 个 Notes 任务通过目标验证，13 个任务失败；另有 2 个 Start 前保护拒绝。406 项审计一致性检查不是任务成功率，这些跨版本、重复任务也不是随机抽样的通用能力基准。后续新版本应另列结果，不能追认旧失败。〔E1〕

**当前已验证普通 App 工具链的默认模型首选是 LFM3-1.7B QAD Q4_0 + Hexagon HTP0。** 依据是相同 APK 下的普通工具任务、后续 Notes 回归、生成阶段普通 Stop 与后台清理证据。它不是通过公开榜单选出的“所有手机任务最强模型”。LFM2.5-8B-A1B 是有实际工具结果的 NPU 对照；Orvena NPU 可用但本例明显较慢；Gemma 4、视觉模型和 35B MoE 的资格应分别评估。〔E1–E4〕

## 1. 先固定平台，再讨论“算力”

| 项目 | 本机 / 本轮事实 | 不能推出的结论 |
|---|---|---|
| SoC | 原版 Snapdragon 8 Elite，SM8750；对应 Hexagon **V79** | 不能套用 8 Elite Gen 5 / SM8850 / **V81** 的性能 |
| 运行日志 | HTP0，V79 skel；硬件元数据 HVX 6、HMX 1、VTCM 8 MB | 不是 TOPS、利用率、实测带宽或所有算子均在 NPU 的证明 |
| 内存 | 16 GB 机型；系统可分配空间还要留给 Android、目标 App 与后台任务 | VTCM 不能当作权重显存；进程 PSS 不能当作整个 DSP/系统内存 |
| offload | 三个文本模型都有实际 HTP 选择与完整层放置日志 | llama.cpp 的通用 “offloaded … to GPU” 字样不能单独证明使用 Adreno |

SM8750/V79 与 SM8850/V81 的对应关系来自 Qualcomm 官方 SDK 支持表 [P1]；HVX/HMX/VTCM 和层放置来自本机日志〔E1〕。Qualcomm 产品页描述了张量、向量、标量加速单元及相对上一代的 AI 提升 [P2]；这些资料没有替本轮量出“本机能持续产生多少 token”。本轮没有独立逐算子硬件剖析、NPU 利用率或能耗测量，因此不填一个推算的 TOPS 数字。

HTP0/HTP1 是运行时设备/会话名，不能据此宣称两颗物理 NPU、独立显存或算力翻倍。量化格式同样不能只按文件名推断：官方 GenieX 文档以 Q4_0 作为常见 Hexagon 路径 [P3]，但本轮 Orvena Q4_K_M 已有 HTP0 实测；最终仍要核对具体架构、张量处理、后端日志与结果。〔E1、E4〕

## 2. 模型选择：把普通任务、诊断与历史记录分开

下表三项均来自 APK SHA 前缀 **2f588a81**、GenieX **v0.10.0 / 071f6099**、`llama_cpp`、NPU/HTP0、8192 上下文的普通 Notes 任务。每项只有一个可比样本；是同类任务，不是同一 token 串。模板、tokenizer 与实际输入长度不同，也没有声称受控冷缓存或长期热稳态。〔E1〕

| 模型与文件 | 输入 / 生成 token | Prefill tok/s | Decode tok/s | SDK profile TTFT | Native request | 后台创建→终态决策 |
|---|---:|---:|---:|---:|---:|---:|
| LFM3-1.7B QAD Q4_0，1.050 GB | 5138 / 129 | 871.33 | **24.09** | 5.897 s | 13.829 s | **23.830 s** |
| LFM2.5-8B-A1B Q4_0，4.845 GB | 5116 / 139 | 595.96 | **20.30** | 8.626 s | 27.804 s | **42.682 s** |
| Orvena-4B Q4_K_M，2.783 GB | 5421 / 132 | 339.62 | **7.54** | 16.044 s | 41.829 s | **54.286 s** |

三者均完成实际 `notes.create`、保存列表、重开正文的验证，并正常关闭本任务模型进程。表中 TTFT 是 SDK profile 字段，不能当作用户按 Start 到首字的完整时间；Native request 包含该回执记录的加载/生成阶段，后台区间排除了更早的 preflight。完整 admission→terminal 单调时钟区间未在该回执完整暴露，不能把采集文件的墙钟时间冒充端到端耗时。〔E1〕

LFM3 官方卡把它定位为本地 agent、结构化输出和专用任务的小模型，支持工具模板；同时明确其小规模对复杂多步推理有局限。官方默认 thinking 和 XML 工具格式也不等同于 Hepta 的既有 JSON 决策协议，需要当前 adapter/grammar 正确绑定。[P6] 选择它的理由包括本机约 1.05 GB 权重、上述工具闭环与 Stop 证据，不能只引用作者在其他芯片上的速度或 BF16 服务端榜单。〔E1、E3〕

LFM2.5 名称里的 A1B 不能解释成“只存 1B 参数”。官方模型卡给出 **8.3B 总参数 / 1.5B 活跃参数**，是混合卷积与注意力的 MoE 文本模型 [P7]；本机约 4.845 GB GGUF 是独立的文件事实。Orvena 本例较慢不证明它在所有任务上更差，但目前没有足够同任务质量收益支持将它替换为默认模型。〔E1〕

### 其他候选的实际资格

- **Orvena GPU**：确实选择了 Adreno 830 / GPUOpenCL、34/34 层；约 5.4K-token 输入时 TTFT 53.372 s，只生成 1 token。控制器 72 s 等待早于 73.017 s 回调，任务进入 blocked，之后通过普通 UI 确认恢复。不能用这 1 token 报稳态 decode 速度，也不能把后续进程退出追认为业务或 SDK 清理成功。〔E3〕
- **Gemma 4 E2B**：现存 profile 精确绑定 3,349,516,256 B 的 QAT Q4_0 GGUF；本次只核 host 源配置，未重新核手机权重。官方 E2B 是 effective 命名，模型卡列 2.3B effective、含 embeddings 5.1B [P8]。本轮早先记录的 core4 仅 1/4 不能升级为普通工具任务通过；由于本报告未重新取得旧 code14/core4 原回执，不列其吞吐、也不猜另外三题的失败类别。当前 APK 下的普通工具资格仍待独立验证。〔E6；历史结论仅作待复核背景〕
- **GUI-Owl-1.5-4B**：已有普通 VLM adapter 和较早 APK **12d86be3** 的两个 Notes 成功记录。一个已审回执为 LM=HTP0、视觉=GPUOpenCL，native 85.688 s；不能称全视觉链纯 NPU。旧 flight 在推理前被主屏保护拒绝，shopping 因空白/透明原图失败；这些不是模型语义成绩，也不是当前 APK 的机票、购物或任意 GUI 资格。〔E2〕
- UI-Venus-2-9B 仅完成主机侧集成准备验证，未真机推理与工具派发；MobiMind-1.5-2B-W8A8 是另一条 MNN 诊断链，不是 MobiInfer 35B。现有公开汇总未给 MAI-UI-2B/8B、GUI-Owl-1.5-2B、UI-Venus-2-27B 当前同 APK 普通控制器资格。模型卡或混合云成绩不能替代这项证据。〔E2〕

LFM3 的普通 Stop 已在首个非空 token checkpoint 后触发，并核对同请求/同 generation、进程身份、取消退出、任务及两层显示租约清理，主屏无输入。纠正的是旧 harness 的字段映射，旧 false 回执保留；checkpoint 不证明点击瞬间某个 NPU 内核正在执行。〔E3〕

## 3. 新运行时值得验证，但需要明确迁移成本

| 路线 | 已核实的一手支持 | 对现 Hepta 的工程成本与本轮边界 |
|---|---|---|
| 现有 GenieX / llama.cpp Hexagon | 当前普通 App 路径已实测；可选择 HTP、OpenCL 或 CPU [P3] | 保留已绑定的模型、模板、grammar、请求/取消/清理协议，最适合作为当前基线。不能把“框架支持 GGUF”视为每个新架构都正确。 |
| GenieX **v0.11.0**，2026-11-12 | 发布说明有 prompt prefix 复用、warmup batch 边界、MTP/HTP、QAIRT 插件生命周期修复；也有标为破坏性变更的 total/cached prompt token 报告 [P4] | 值得单独 A/B；需审 SDK ABI、token 计数、模板、缓存隔离、取消和普通任务。Android 文档依赖更新与所有平台发行包不是同一件事。它不会自动修好网页证据或无障碍树缺失；本轮未替换已验证的 0.10。 |
| QAIRT / QNN、AI Hub 预编译包 | 官方按目标芯片/量化/图编译发布 bundle；与通用 GGUF 路径不同 [P1]、[P3] | 要匹配 SM8750/V79、SDK/HTP 库、算子、prefill/decode 图、上下文及 KV 布局，再接 App UID worker 和工具协议；不能拿 V81 包或别的静态形状直接认定兼容。 |
| LiteRT / LiteRT-LM | Google 官方 samples README **明确列出 Gemma 4 E2B 在 Snapdragon 8 Elite NPU** 的多模态样例 [P5] | 值得作为 Gemma 候选路线；`.litertlm` 与现有 GGUF 不是同一文件格式。须核具体模型包、V79 编译/装载、NDK/JNI、流式取消及 App 绑定。本报告没有证明某个未核实的 SM8750 下载文件已经可直接替换，也未新集成 SDK。 |
| ExecuTorch Qualcomm backend | 官方 Llama 3 3B Android 教程包含量化、分片、图转换和 `.pte` 导出 [P9] | 可控但迁移较重：模型导出/校准、静态形状、编译链、tokenizer 与工具输出都需接入。官方该示例还列出较高 host 内存和小时级导出成本；这不是仅换一个模型文件，也不能外推为每个模型的成本。 |

这些路线都可以完全在手机上推理；“不接外部大模型”与“查询官网时不联网”是不同要求。网页 helper 可以访问服务页面，而模型推理和工具决策保持本地。反过来，网页页面/证据未就绪时更换更大的模型不会使任务自动完成：已归档自然价案例在进入模型前就因原生观察拒绝及后续 RPC 预算耗尽失败。〔E1、E5〕

## 4. 大 MoE 可以跑，但现有 35B 结论只到 standalone

MobiInfer Android v0.4.5（2026-11-11）通过外置专家、HTP tiled 布局、前瞻读取与可选 DSpark 减少常驻专家内存，并隐藏部分闪存 I/O [P10]。以下必须分成作者测量与本机测量：

| 来源 / 平台 | 配置与输入 | Decode |
|---|---|---:|
| 作者仓库：8 Elite Gen 5 / V81 | Q3 tiled、跨层流水、O_DIRECT、DSpark3，260-token prompt | 23.3 tok/s；其他 App 前台时 21.3–21.8 |
| 作者仓库：OnePlus 13 / 原版 8 Elite | Q3、LES+DSpark，41 / 512-token prompt | 17.98 / 13.65 tok/s |
| **本机 razr / V79，note-json** | trained top-8、context 2048；115-token prompt；DSpark/vision 关闭 | **4.37 tok/s，18 eval runs** |
| **本机 razr / V79，adversarial-json** | 同冻结配置；142-token prompt | **4.62 tok/s，32 eval runs** |

作者数字不是本机承诺；本机没有开启 DSpark，prompt、上下文、功耗模式和 runner 也不同。两次本机 prefill 为 22.68、17.27 tok/s；首个被捕获 stdout 为 7.707、11.937 s，不能直接称独立测量的模型 TTFT。取消样本是中断的 5 eval runs，也不作为长时稳态速度。〔E4；作者数据见 P10〕

本机使用 OpenBMB 的 MiniCPM-V 4.7 35B-A3B，经 **fengerhu1** 发布的 GGUF/Hexagon 转换包；应区分原模型作者与转换作者 [P11]、[P12]。固定 45 文件包共 **19,315,173,512 B**，包括本次未使用的视觉和 drafter 资产。本次只验证了两个固定 mock JSON 与一次取消；41/41 层 offload、正常结束/取消和 owned process tree 清理有证据，但没有独立逐算子 NPU profiling。〔E4〕

原 harness 对两次完整 stdout 的判定仍为失败，因为 CLI 在 JSON 后写入固定 EOG 后缀；独立离线复核仅按固定源码版本去除该控制台后缀，重验原 SHA、完整严格 JSON、退出和清理条件，并保留旧回执。**这不是 Hepta App UID 推理资格，不是普通工具 dispatch，更不是购买或查询业务成功。** 115/142-token 短提示也没有验证 Hepta 的约 5K-token 控制器上下文。〔E4〕

内存方面，本次 `LLAMA_MOE_IO_POOL=1` 避开了已定位的 O_DIRECT 临时线程 scratch 生命周期问题。它是单进程工作方式的缓解措施；生产化仍需正确释放 TLS scratch、处理线程池构建失败，并验证重复上下文/取消。解码段 child PSS 约 0.13 GiB，较高峰值约 0.5 GiB，**都不能当成整个 35B 模型 RAM**：共享 DSP、系统和文件缓存不完整归属该进程。观察到系统 MemAvailable 最低仍约 5.72 GiB，不能据此宣称任意更长任务都安全。〔E4；固定源码 P13〕

## 5. 为什么 24B / 35B 不能只按“活跃参数”算内存

理想化的纯权重下限是：

`总参数 × 每参数位宽 ÷ 8`

若所有参数恰好 4-bit，24B 约 **12 GB / 11.18 GiB**，35B 约 **17.5 GB / 16.30 GiB**。这只是算术下限，尚无量化 scale、混合精度层、对齐、KV/循环状态、计算 buffer、运行库与 Android/目标 App。Dense 24B 和 MoE 24B 也不是同一种计算负担；本轮没有 24B 普通 App 资格。

MoE 的活跃参数决定一次 token 主要计算多少专家，不能抹掉全部专家权重的存储。UFS expert offload 是将专家保留在闪存、按需搬入并管理有限缓存/槽位，代价是读取、页缓存、预取错误和设备带宽竞争。提高上下文、视觉输入或批次还会改变内存与延迟。Gemma E2B 的 effective 命名、LFM2.5 的 A1B 命名与 35B-A3B 都应查总参数、真实文件和运行时分配，不能单凭后缀估容量。[P7、P8、P10；E4]

## 6. 工程优先级

继续以 **LFM3 / HTP0 / 8192 context / 4 threads** 的已绑定普通 App 路径作为基线；保留 LFM2.5 和 Orvena 的同任务对照。新的 runtime、Gemma 或视觉候选只有在同 APK、真实授权、相同目标、取消/清理与主屏保护下获得收益，才足以改变默认配置。35B 先完成 App UID、长控制器提示、严格 grammar 和任务/显示/观察绑定，再谈替换主控。〔E1–E4〕

现有控制器有通用观察→模型→校验→动作循环，但成功判断仍依赖目标专用的完成证据；任意自然语言、任意 App、下单付款没有因这些局部成功而获得资格。当前价/规格任务还涉及真实页面绑定与商品规格证据，单纯增大模型不会补上缺失的验证路径。〔E2、E5〕

## 复核索引

本机数据引用已保存的 E1–E6 原件，完整 SHA-256、版本和来源范围见 [配套来源清单](NPU-MODEL-RESEARCH-SOURCES.json)。本报告没有改写原回执，也没有新增测试。

| 编号 | 已有证据 | 本文用途 |
|---|---|---|
| E1 | PHONE-VALIDATION-DRAFT.json，SHA 前缀 `0bbcb5f0` | 21任务口径；同APK三模型性能/普通Notes |
| E2 | HISTORICAL-CAPABILITY-SCOPE-c662.json，`e509c0c6` | 视觉候选及通用动作/专用完成验证边界 |
| E3 | STOP-GPU-VALIDATION.json，`4332f478` | LFM3停止；Orvena GPU失败与恢复 |
| E4 | MOE-35B-STANDALONE.md，`72029bcc` | 35B本机独立推理/内存/取消，不含App业务 |
| E5 | NATURAL-PRICE-5DFA-DIAGNOSIS.public.json，`316fea3f` | 本地模型未启动的真实观察瓶颈 |
| E6 | 冻结 ModelProfile.java，`11ff3d26` | 模型文件/架构配置，不冒称手机再验 |

一手来源均于 **2026-11-16** 复核；可变 main 页面只代表该复核时间，固定模型/运行时另保留 revision。P10–P13 分别区分运行时作者、原模型作者和转换作者：

- [P1 · Qualcomm：QAIRT SDK supported Snapdragon devices][P1]。
- [P2 · Qualcomm：Snapdragon 8 Elite Mobile Platform][P2]。
- [P3 · Qualcomm：GenieX platform and quantization documentation][P3]。
- [P4 · Qualcomm：GenieX v0.11.0 release][P4]（发布 2026-11-12）。
- [P5 · Google AI Edge：LiteRT and LiteRT-LM samples][P5]。
- [P6 · Liquid AI：LFM3-1.7B model card][P6]。
- [P7 · Liquid AI：LFM2.5-8B-A1B model card][P7]。
- [P8 · Google DeepMind / Google AI for Developers：Gemma 4 model card][P8]。
- [P9 · PyTorch / ExecuTorch：Run Llama 3 3B Instruct on Android with Qualcomm backend][P9]。
- [P10 · IPADS-SAI：MobiInfer Android pinned README][P10]（发布 2026-11-11）。
- [P11 · OpenBMB：MiniCPM-V-4.7-35B-A3B model card][P11]。
- [P12 · fengerhu1：Pinned MiniCPM-V-4.7-35B-A3B GGUF/Hexagon conversion][P12]。
- [P13 · IPADS-SAI：Pinned expert slot implementation][P13]。

[P1]: https://docs.qualcomm.com/nav/home/QNN_general_overview.html?product=924033590759186372
[P2]: https://www.qualcomm.com/smartphones/products/8-series/snapdragon-8-elite-mobile-platform
[P3]: https://github.com/qualcomm/GenieX/blob/main/docs/en/get-started/platforms.mdx
[P4]: https://github.com/qualcomm/GenieX/releases/tag/v0.11.0
[P5]: https://github.com/google-ai-edge/litert-samples/blob/main/README.md
[P6]: https://huggingface.co/LiquidAI/LFM3-1.7B
[P7]: https://huggingface.co/LiquidAI/LFM2.5-8B-A1B
[P8]: https://ai.google.dev/gemma/docs/core/model_card_4
[P9]: https://docs.pytorch.org/executorch/main/llm/build-run-llama3-qualcomm-ai-engine-direct-backend.html
[P10]: https://github.com/IPADS-SAI/Mobiinfer-Android/blob/659c3cb5a38493147444a47e0e0762664aacba06/README.md
[P11]: https://huggingface.co/openbmb/MiniCPM-V-4.7-35B-A3B
[P12]: https://huggingface.co/fengerhu1/MiniCPM-V-4.7-35B-A3B-gguf-hexagon/tree/f125f5a71552e70ccc2d5b0061f77f311bee70c5
[P13]: https://github.com/IPADS-SAI/Mobiinfer-Android/blob/659c3cb5a38493147444a47e0e0762664aacba06/src/llama-moe-slot.cpp
