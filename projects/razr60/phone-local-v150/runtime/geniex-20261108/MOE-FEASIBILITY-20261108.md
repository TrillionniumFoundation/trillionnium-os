# 更大 MoE 在 Snapdragon 8 Elite 上的可行性

研究日期：2026-11-08。目标机为 Motorola XT2551-3、SM8750、Hexagon v79、Adreno 830；实测物理内存为 15,540,960 KiB（约 14.82 GiB）。本文区分模型作者/项目作者的结果、固定源码能力，以及本机已经完成的测试。**本文没有声称已在本机运行任何 MoE 模型。**

## 决策

更大 MoE 有可实施路线。优先级由完整任务表现决定：中文指令、屏幕理解、正确动作、延迟和内存峰值必须一起验证。

当前 Hepta 集成继续使用已完整下载的 Qwen3-VL-4B QAIRT W4A16 / SM8750-v79 包完成验收。该包的语言和视觉图都针对目标芯片编译，模型已有实际断网加载与视觉测试；最终状态见 `VALIDATION.md`。更大 MoE 是独立的容量/质量实验，尚不作为默认模型。

30–35B 级多模态候选以 **Qwen3.6-35B-A3B + 有界专家缓存 + 闪存按需读取** 最值得进一步试验。它具备原生视觉；普通 Q4 文件超过手机可用内存，需要专门的专家流式运行时。不能把 A3B 理解为只需保存 3B 参数，也不能由激活参数量推导手机吞吐。[1][2]

较小的常驻 MoE 研究候选优先选 **LFM2.5-8B-A1B**。官方卡实际列出 8.3B 总参数和 1.5B 激活参数，不能只由名称推成 1.0B。它是支持中文和工具调用的文本模型，需配合另一视觉模型或可靠的 UI 结构读取；不能直接接收截图替代当前 4B VLM。它也需要为 reasoning 输出重新制定延迟/输出预算。[14]

## 容量判断

按权重数量计算，35B 参数的纯 4-bit 数据下限约为 17.5 GB（十进制），2-bit 下限约为 8.75 GB。这只是乘法估算，未计量化比例因子、保留高精度的层、视觉编码器、KV/cache、运行时和操作系统。手机 GPU/NPU 使用系统内存，不能把同一份 RAM 再计算为一份额外显存。

最新一次推机前只读基线的 MemAvailable 为 7,537,732 KiB（约 7.19 GiB）；这不是保证可全部分配给模型的固定额度。后续配置必须测量加载峰值和运行峰值，而不能仅比较下载压缩包大小。

| 候选 | 模型/文件事实 | 对本机的意义 | 目前证据边界 |
| --- | --- | --- | --- |
| LFM2.5-8B-A1B | 8.3B 总参数、1.5B 激活；官方 Q4_0 为 4,844,678,368 B，Q4_K_M 为 5,155,564,768 B | 较有希望完整驻留内存的文本 MoE，需要额外屏幕理解路径 | 固定源码有相关短卷积/专家 kernel；未在本机验证 [14][15] |
| Granite 4.0 H Tiny | 7B 总参数、约 1B 激活；官方 Q4_K_M 为 4,230,976,352 B；文本模型 | 相邻尺寸备选，Mamba2 的算子覆盖需要特别核对 | 当前固定 Hexagon 源码未见 SSM_SCAN 支持，不能声称全 NPU [16] |
| Qwen3.6-35B-A3B | 35B 总参数、约 3B 激活；原生视觉；ggml-org 发布的 Q4_K_M 约 20.4 GB，Q8_0 视觉组件约 614 MB | 需要专家缓存/闪存流式；是大模型视觉路线的优先研究候选 | BigMoeOnEdge 作者有 Android 运行结果；本机未运行 [1][2][3] |
| Qwen3-VL-30B-A3B-Instruct | 30B 总参数、约 3B 激活；模型作者明确列出 GUI agent 能力 | 较早的视觉 MoE 备选，仍需解决完整权重容量 | 不以公开 GUI 指标代替这台手机的端到端测试 [4] |
| Gemma 4 26B A4B | 原生多模态 MoE；官方 Q4_0 加载内存估计约 14.4 GB，另需 KV/运行内存 | 当前手机余量不足以直接采用该加载方式 | 只能作为进一步流式/量化研究候选 [5] |
| Phi-tiny-MoE | 约 3.8B 总参数、1.1B 激活；文本模型 | 提供 v79 MoE 运行链路的参考，但不满足“更大视觉模型”的目标 | RunAnywhere 作者报告 SM8750 上约 5–7 token/s；不是本机实测 [6][7] |
| Bonsai-27B 1-bit | 约 3.9 GB 语言权重；可另配约 0.63 GB 视觉组件 | 是扩大参数量的另一条低位压缩路线，**不是 MoE** | 作者的 4K 语言推理峰值约 5.2 GB；未确认本机 v79 完整兼容 [8] |

不同量化发布者的 Q4_K_M 文件可能分别约 20.4 GB 和 22.3 GB，不能把它们当作同一文件，也不能直接混用其性能数据。Bonsai 使用专门的 Q1_0_g128 格式和作者维护的运行时；名称相似的通用 Q1 支持不构成端到端兼容证明。

## 可直接研究的工程路线：BigMoeOnEdge

作者的 Qwen3.6-35B-A3B Android 实验使用约 22.3 GB 的量化模型与 12 GB 内存手机。保留模型原来的 top-8 路由时，3,000 MiB 专家缓存的单次 96-token 结果约为 5.0 token/s。该结果不包含模型加载和 prompt prefill，也未说明就是本机 SM8750，因此仅证明这种容量路线可运行。[2]

它的 Hexagon 路线把 prefill 放在 NPU，decode 留在 CPU，减少逐 token 的 CPU/DSP 跨域开销。作者的详细 NPU 数据来自 v81。发布包中含 v79 DSP 库不等于已经在 v79 完成实机验证。[9][10]

实现重点是限制专家缓存、按路由读取权重，并在计算期间安排下一批读取。单纯对大于 RAM 的文件使用 mmap 可能出现长时间缺页等待，平均速率会掩盖单步卡顿。降低 top-k 专家数量会改变原模型计算，必须另报质量结果；本项目不把这类有损设置混入原模型基线。

## 当前固定 Hexagon 源码的新能力

本次 GenieX v0.10.0 包固定使用 llama.cpp commit `19cce6919992fdffd92e0ac152caaf1e2b8f254e`。实际读取该版本 `ggml-hexagon` 源码后可确认：MoE 使用的 `MUL_MAT_ID` 检查分支接受的量化类型已经包括 Q1_0、Q2_0、Q2_K、Q3_K、Q4_0、Q4_1、Q4_K、Q5_K、Q6_K、Q8_0、IQ4_NL 和 MXFP4。[11]

因此，较早文档中“低于 Q4 的专家不能走 Hexagon”的概括，不能直接套用到当前固定版本。仍然必须通过张量类型、布局、块对齐、精度、shape 和实际 kernel 检查；源码接受某个量化类型，不保证整张视觉/混合注意力图能在 NPU 上执行，也不证明数值正确或闪存流式已集成。

源码证据：

- `ggml/src/ggml-hexagon/ggml-hexagon.cpp`，blob `cf2e37aa6eafe3b61252584e9e29f127c50d9535`，后端支持检查委托给 `htp_kparams_check`。
- `ggml/src/ggml-hexagon/htp-kparams.cpp`，blob `b8d1aee3d0e374d675d96110d8007a5453959780`，`htp_matmul_check_types` 的 `is_matmul_id` 分支。

LFM 的短卷积路径使用 `SSM_CONV`，当前固定 Hexagon 版本存在受 dtype、kernel 大小和布局约束的对应检查/执行路径。Granite Mamba2 还需要 `SSM_SCAN`；该固定版本的 Hexagon 检查表没有该操作。这个区别使 LFM 更适合作为优先源码适配实验，但两者的全图、量化数值和性能仍需实机验证。

本机现有 2B GGUF 试验确认了真实 v79 FastRPC 会话、HVX/HMX/VTCM 信息及层卸载，但它是稠密模型；不能把约 35 token/s 的该项结果移植为 35B MoE 的性能预测。

## 2026 年最新技术应如何解读

BigMoMo（2026-09）研究以多 token 投机窗口组织专家读取，并与 NPU 计算重叠；摘要报告了最高 30B 模型实验。它提供值得借鉴的调度方向，本次未确认与 razr、所选权重及部署工具链完全匹配的可运行组合。[12]

高通 2026-09 的 30B MoE / StepEdge-Omni 展示使用更新的 Snapdragon 8 Elite Extreme Gen 6 参考平台。本机是 SM8750 / v79；不能直接把新平台的性能、内存增强或模型包兼容性归给这台手机。[13]

## 如果继续推进大 MoE，验收顺序

1. 固定模型和所有量化/视觉文件的版本、SHA、原始路由数、上下文和视觉输入策略。保存无损路由基线。
2. 在独立目录运行，测量实际可用内存、加载峰值、专家缓存、每 token 闪存读取、热态和冷态延迟；不给系统 RAM 预留设置凭空保证值。
3. 先核对纯 CPU 的输出和模型正确性，再逐项启用 NPU prefill，比较数值、中文理解与屏幕定位；分别记录 CPU、GPU、NPU 和回退的算子。
4. 固定相同 prompt 与输出长度，报告 TTFT、prefill、decode 和完整动作决策时间。短 agent 回合要计入加载、视觉、prefill 和结果解析。
5. 通过严格动作结构、坐标/截图绑定、取消与进程回收，再进入 Hepta 的真实可逆 App 测试。模型能够加载不等于能够可靠操作 App。

## 主要原始来源

1. Qwen 模型卡：https://huggingface.co/Qwen/Qwen3.6-35B-A3B
2. BigMoeOnEdge 作者 benchmark：https://github.com/Helldez/BigMoeOnEdge/blob/main/docs/benchmarks.md
3. ggml-org 实际文件列表：https://huggingface.co/ggml-org/Qwen3.6-35B-A3B-GGUF/tree/main
4. Qwen3-VL-30B-A3B 模型卡：https://huggingface.co/Qwen/Qwen3-VL-30B-A3B-Instruct
5. Google Gemma 核心文档：https://ai.google.dev/gemma/docs/core
6. Microsoft 模型卡：https://huggingface.co/microsoft/Phi-tiny-MoE-instruct
7. RunAnywhere 作者 SDK/性能表：https://github.com/RunanywhereAI/runanywhere-sdks
8. Prism ML 作者模型卡：https://huggingface.co/prism-ml/Bonsai-27B-gguf
9. BigMoeOnEdge 平台说明：https://github.com/Helldez/BigMoeOnEdge/blob/main/docs/platforms.md
10. BigMoeOnEdge NPU 实验：https://github.com/Helldez/BigMoeOnEdge/blob/main/docs/npu-prefill.md （读取的 blob：`b094dd78f10b65c7e192932587ee0fd18d815688`）
11. 固定 Hexagon kernel 检查源码：https://github.com/ggml-org/llama.cpp/blob/19cce6919992fdffd92e0ac152caaf1e2b8f254e/ggml/src/ggml-hexagon/htp-kparams.cpp
12. BigMoMo 论文摘要：https://arxiv.org/abs/2609.14643
13. 高通 2026-09-22 发布材料：https://www.qualcomm.cn/news/releases/2026/09/releases-2026-09-22-2
14. Liquid AI 模型卡：https://huggingface.co/LiquidAI/LFM2.5-8B-A1B
15. Liquid AI 官方 GGUF 清单：https://huggingface.co/LiquidAI/LFM2.5-8B-A1B-GGUF/tree/49c14831707011e64d70b2ebd8462ba08d608434
16. IBM 模型卡：https://huggingface.co/ibm-granite/granite-4.0-h-tiny ；官方 GGUF：https://huggingface.co/ibm-granite/granite-4.0-h-tiny-GGUF/tree/08d5a8a9741dd5c1a95d2d39e25253226aa1464e
