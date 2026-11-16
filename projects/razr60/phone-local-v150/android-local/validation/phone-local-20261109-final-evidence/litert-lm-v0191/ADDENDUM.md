# LiteRT-LM v0.19.1 技术补充：Gemma 4 GPU／MTP 与 Snapdragon 8 Elite NPU 路线

核验日期：2026-11-09 UTC。本文是独立技术研究附件，不替换既有 Hepta 测试报告，不修改已冻结源码、候选或设备状态。

## 1. 结论与证据级别

**优先值得准备的是 LiteRT-LM v0.19.1 + Gemma 4 E4B 基础包的 GPU 实验，并将 MTP 关闭／开启作为同一包内的对照。** 该版本已提供真实工具对话、逐次约束、明确取消和可分离的 engine／conversation 生命周期。不过，保留 Hepta 的逐步原始输出证据与动作权限门仍需一个新适配器，不能只改模型文件路径。

**Gemma 4 E2B 的 SM8750 NPU 路线保留为有条件的后续实验。** 官方示例确实针对 Snapdragon 8 Elite，但示例依赖、旧模型指针和最新运行时不是同一套已验证组合。官方模型历史已明确删除过 SM8750 文件；不能把旧缓存页面、当前 QCS8275 文件或 NPU_Uncompiled 文件当作当前可直接部署的 SM8750 包。

本轮仅完成公开官方源码、发布元数据、模型指针和历史记录核查，以及保存这些文本证据的哈希核验。没有下载模型权重、AAR、SDK 或运行时二进制，没有编译 LiteRT-LM，没有推理、手机访问或设备状态变更。本文所有性能收益、模型任务能力及集成步骤均标明为待验证或设计建议。

### 版本基线

| 项目 | 本轮固定的身份 |
|---|---|
| LiteRT-LM release | v0.19.1，发布于 2026-11-05 21:57:29 UTC |
| LiteRT-LM 源码 commit | `7a03724cece417f1724c923b3d527b4319730841` |
| 该版本 C ABI | 1.0.0；不是旧 0.x C API 的二进制兼容升级 |
| Qualcomm Android sample commit | `163222b0a76d2e80f959c1fc1f1918420e3b1e4d` |
| HF E4B 本轮网页显示的仓库 head | `71064b01bd5e2bfd9a5f9dd52df86ae4800138c1` |
| HF E2B 本轮网页显示的仓库 head | `3d48132a00cf76de57d926de30f5c5c5ed9b8c0d` |

GitHub release API 和 tag API 已实际读取，tag 直接指向上述 commit。v0.19.1 的发布说明新增 Artisan GPU 的 Gemma 4 视觉／音频支持与视觉双向注意力。该 tag 的 README 仍保留 v0.19.0 小节，描述 GPU logit masking、与 MTP 的组合支持及 C ABI 变更。这是文档栏目未随补丁号更新，不能用 README 小节把实际最新 release 改写成 v0.19.0。[发布说明](https://github.com/google-ai-edge/LiteRT-LM/releases/tag/v0.19.1)；[release API](https://api.github.com/repos/google-ai-edge/LiteRT-LM/releases/tags/v0.19.1)；[tag API](https://api.github.com/repos/google-ai-edge/LiteRT-LM/git/ref/tags/v0.19.1)；[固定 README](https://github.com/google-ai-edge/LiteRT-LM/blob/7a03724cece417f1724c923b3d527b4319730841/README.md)。

HF 的 API 请求在本研究工具中返回不可访问；下文 HF head、列表和历史结论来自可访问的官方当前网页及固定 commit 页，而不是声称取得了实时 HF API 响应。若网页带缓存，按其明确的 commit、文件指针及页面日期使用，不用相对“几天前”换算发布日期。实际入库的来源类型见 `SOURCE-INDEX.json`。

## 2. C++／C／Kotlin 的集成合同

| 能力 | v0.19.1 已核实的接口 | Hepta 必须处理的边界 |
|---|---|---|
| 真实工具对话 | C++ `JsonPreface.messages/tools`、`Conversation::SendMessage/SendMessageAsync`、`GetHistory`；C 的 config set_tools/set_messages + message JSON；Kotlin `Message.user/model/tool` 和 `initialMessages` | 原用户目标只进入一次；后续用真实模型 assistant/tool_calls 和实际 tool 观察。不得把推测的执行成功写成 tool 回执 |
| 手动控制工具执行 | C++／C 交回结构化消息；Kotlin `automaticToolCalling=false` | Kotlin 默认是 true；必须关闭 SDK 自动工具循环，动作先进入 Hepta 验证器与独立 collector |
| 每次调用更新约束 | C++ `OptionalArgs.decoding_constraint`；C `litert_lm_conversation_optional_args_set_constraint`；Kotlin `sendMessage(..., responseFormat=...)` | 每次绑定当前不可变 observation／catalogue／目标集合，不使用宽泛 dict schema 代替权限检查 |
| 约束语法 | C++ LLGuidance 支持 regex、JSON Schema、Lark 等；C 公共 enum 和 Kotlin ResponseFormat 暴露 regex／JSON Schema | 现有 llama.cpp GBNF 不能原样传入这些接口，需等价编译与拒绝测试 |
| 显式取消 | C++ CancelProcess／CancelGroup；C conversation_cancel_process；Kotlin cancelProcess | 取消是异步请求；callback 可能迟到；取消后的 conversation／session 不可复用 |
| 模型与会话分离 | engine 管模型资源；各 session／conversation 管内部状态；可由同一 engine 创建新 conversation | 可设计任务内 warm engine，但状态清理、内存释放、进程终态须重新验收 |
| 原始输出 | 底层 C++ `Responses::GetTexts()` 有解码文本；高层 Conversation 先经过 model data processor／channel 解析 | 高层 JSON 或 Kotlin Message 不能直接标记为“解析前原始输出” |

接口原件：[C++ conversation](https://github.com/google-ai-edge/LiteRT-LM/blob/7a03724cece417f1724c923b3d527b4319730841/runtime/conversation/conversation.h)、[C++ engine](https://github.com/google-ai-edge/LiteRT-LM/blob/7a03724cece417f1724c923b3d527b4319730841/runtime/engine/engine.h)、[C++ I/O](https://github.com/google-ai-edge/LiteRT-LM/blob/7a03724cece417f1724c923b3d527b4319730841/runtime/engine/io_types.h)、[C conversation](https://github.com/google-ai-edge/LiteRT-LM/blob/7a03724cece417f1724c923b3d527b4319730841/c/conversation.h)、[C engine](https://github.com/google-ai-edge/LiteRT-LM/blob/7a03724cece417f1724c923b3d527b4319730841/c/engine.h)、[Kotlin Config](https://github.com/google-ai-edge/LiteRT-LM/blob/7a03724cece417f1724c923b3d527b4319730841/kotlin/java/com/google/ai/edge/litertlm/Config.kt)、[Kotlin Conversation](https://github.com/google-ai-edge/LiteRT-LM/blob/7a03724cece417f1724c923b3d527b4319730841/kotlin/java/com/google/ai/edge/litertlm/Conversation.kt)、[Kotlin Message](https://github.com/google-ai-edge/LiteRT-LM/blob/7a03724cece417f1724c923b3d527b4319730841/kotlin/java/com/google/ai/edge/litertlm/Message.kt)、[Kotlin ResponseFormat](https://github.com/google-ai-edge/LiteRT-LM/blob/7a03724cece417f1724c923b3d527b4319730841/kotlin/java/com/google/ai/edge/litertlm/ResponseFormat.kt)。

### 2.1 工具对话可保留，但不能交出执行权

Kotlin 的 Role 确有 system、user、assistant、tool；Message 可保留 toolCalls 和 channels。C++ 的 conversation 会保留真实 assistant 响应到历史，工具结果再作为后续 message 进入同一 conversation。适配器应记录完整 typed message，而非只记文本。

两个容易漏掉的行为已在固定源码中确认：

1. Kotlin 的 automaticToolCalling 默认 true，内部会执行工具并继续调用模型，最多循环 25 次。它还会在启用自动工具、存在工具且当前不是 tool response 时忽略显式 responseFormat。Hepta 必须设 false，逐次自行派发。
2. Kotlin `Message.toString()` 只返回 contents 的字符串，不等价于完整消息，不能据它保留 toolCalls／channels，也不能据它重建原始模型字节。

因此，建议入口是“模型返回候选工具调用 → 原样保存 → Hepta 校验 observation、当前目标集合、取消状态与 owner → 真实派发 → 收集实际 UI → 生成 tool 回执”。拒绝也应真实记录为拒绝；不能把错误模型动作改成正确动作后再冒充原输出。[固定实现](https://github.com/google-ai-edge/LiteRT-LM/blob/7a03724cece417f1724c923b3d527b4319730841/kotlin/java/com/google/ai/edge/litertlm/Conversation.kt)；[Message 序列化](https://github.com/google-ai-edge/LiteRT-LM/blob/7a03724cece417f1724c923b3d527b4319730841/kotlin/java/com/google/ai/edge/litertlm/Message.kt)。

### 2.2 每步约束存在，但必须主动更新和验证构建能力

C++ 的 `CreateDecodeConfig` 会在存在 decoding_constraint 且 provider 非空时创建新 constraint；如果本次省略该参数，已有成员 `constraint_` 可继续被使用。因此不能把“本次没有传约束”理解为“自动清掉上次约束”。安全实现应每个决策都明确传入本步约束，记录其 SHA，并拒绝 provider 初始化失败。[固定实现](https://github.com/google-ai-edge/LiteRT-LM/blob/7a03724cece417f1724c923b3d527b4319730841/runtime/conversation/conversation.cc)。

C++ 的 LLGuidance 配置能接 JSON Schema 和 Lark；C／Kotlin 的公共高层类型目前只有 regex／JSON Schema。未来若保留原生 Gemma tool 语法，需要证明原生调用格式、当前工具／目标联合目录及约束是一致的，不能只约束一个普通 JSON 对象而假定原生 tool parser 会按相同语义处理。[LLGuidance 类型](https://github.com/google-ai-edge/LiteRT-LM/blob/7a03724cece417f1724c923b3d527b4319730841/runtime/components/constrained_decoding/llg_constraint_config.h)；[C 参数转换](https://github.com/google-ai-edge/LiteRT-LM/blob/7a03724cece417f1724c923b3d527b4319730841/c/conversation.cc)。

源码中存在真正的 feature gate：CMake 要求 `LITERT_LM_ENABLE_CONSTRAINED_DECODING` 和 `LITERT_LM_ENABLE_LLGUIDANCE`，否则可链接到返回 Unimplemented 的 noop provider。头文件有函数或 Android 包能加载，都不足以证明约束已经启用。新候选必须记录实际 AAR／ELF 哈希、构建选项、运行中的 C ABI，并验证不合法目标、额外字段、错误枚举和越界数字不会被接收。[CMake gate](https://github.com/google-ai-edge/LiteRT-LM/blob/7a03724cece417f1724c923b3d527b4319730841/runtime/components/constrained_decoding/CMakeLists.txt)；[noop 的明确错误](https://github.com/google-ai-edge/LiteRT-LM/blob/7a03724cece417f1724c923b3d527b4319730841/runtime/components/constrained_decoding/llg_constraint_provider_noop.cc)。

C ABI 1.0.0 应在首次调用前通过 `litert_lm_get_api_version` 检查主版本和最小次版本；失败函数改为状态返回＋out 参数，不能复用旧函数指针签名。[ABI／线程合同](https://github.com/google-ai-edge/LiteRT-LM/blob/7a03724cece417f1724c923b3d527b4319730841/c/engine.h)。

### 2.3 原始输出保留需要一个明确的 native 观测点

高层 Conversation 的内部 callback 先把 `Responses::GetTexts()[0]` 累积，再识别 thinking／tool 通道并交给 model data processor。C 的 json_response_get_string 返回的是该层消息 JSON；Kotlin 再把它转换成 Message。开启 stream_tool_calls 可看到工具通道片段，但其输出有通道划分，不能据此承诺包含所有原始分隔符、全部文本及失败尾部。[内部 callback](https://github.com/google-ai-edge/LiteRT-LM/blob/7a03724cece417f1724c923b3d527b4319730841/runtime/conversation/internal_callback_util.cc)；[C response 接口](https://github.com/google-ai-edge/LiteRT-LM/blob/7a03724cece417f1724c923b3d527b4319730841/c/conversation.h)。

要保持当前 Hepta 的严格“原模型输出—解析—动作—观察”链，建议新 native bridge 在 **进入上述解析器之前**追加只读输出观察点，保留每个原始解码文本块、顺序、终态／错误、完整拼接文本 SHA，同时另存结构化消息。每条记录绑定 task generation、step、实际模型文件 SHA、engine 配置 SHA、prompt/template SHA、constraint/catalogue SHA。该观察点必须原样转发，不能替换输出。

如果不修改高层 Conversation，则可研究底层 Session 的 Responses API 自行管理模板和对话，但这会扩大历史、KV 与角色模板责任，不能称为直接替换。当前没有验证现成 Android AAR 提供了解析前完整输出回调；这是首轮 adapter 的真实缺口。

## 3. 任务内 warm engine 与取消边界

以下是建议设计，不是已实现或已测结果：

1. **每任务创建一次 engine。** 绑定模型、运行时、量化包、backend、上下文、模板与采样身份；在任务入口校验模型内容与只读文件身份。不能跨未知文件替换复用，仅用文件名或 mtime 作为“同模型”。
2. **同任务使用一个真实 conversation。** 原用户目标一次输入；后续保留真实 assistant 工具调用和 tool 观察。各步新建约束状态并传入当前目标集合。若预算不足，应生成可审计的历史裁剪记录，不能静默丢失当前操作节点或有序目标证据。
3. **若首轮只验证加载复用，另选每步 fresh conversation。** engine 保持，conversation 每步销毁并由确切历史重新创建。它较容易隔离 KV，但仍有 prefill 成本；与真正增量对话是两个实验，应分别计时。
4. **Stop 先撤销派发资格，再请求取消。** 用 task generation／epoch 拒绝迟到 callback；等待最终取消／完成回调和 native 工作停止，之后销毁 conversation。C 头文件明确 cancel 返回后 callback 仍可运行，取消后的会话不能重用。
5. **任务结束后释放 engine。** 初版仅做任务内复用，避免把跨任务常驻、跨任务 KV 隔离和后台常驻内存问题一起引入。新任务创建独立生命周期。不得为了 warm engine 延长现有每步及整任务限时。

C API 的 handle 不是线程安全对象；同一 handle 的调用不得重叠，callback 中除特定取消路径外不能重入同 engine 的 API。应让串行 worker 管理所有生命周期，UI 的 Start／Stop 只发受控请求。Kotlin Flow 当前 `awaitClose {}` 没有主动调用 native cancel，因此“取消收集 Flow”不等价于“推理已停止”。[C 线程与取消合同](https://github.com/google-ai-edge/LiteRT-LM/blob/7a03724cece417f1724c923b3d527b4319730841/c/engine.h)；[C cancel 说明](https://github.com/google-ai-edge/LiteRT-LM/blob/7a03724cece417f1724c923b3d527b4319730841/c/conversation.h)；[Kotlin Flow 与 cancel](https://github.com/google-ai-edge/LiteRT-LM/blob/7a03724cece417f1724c923b3d527b4319730841/kotlin/java/com/google/ai/edge/litertlm/Conversation.kt)。

销毁前仍需确认库的实际异步 drain 行为；仅看到 close/delete 被调用不算 cleanup 完成。若取消不能在原定截止时间内稳定收束，应由宿主处理其独占 worker 并取得退出证据，不能提前报告 idle 或把旧 conversation 交给下一任务。模型常驻还会增加峰值内存持续时间；权重体积不等于总内存，KV、视觉／音频 encoder、MTP drafter 和 backend buffer 要分开记录。

## 4. 模型包与 SM8750 历史差异

以下 SHA 是 **官方指针／文件页宣告的模型对象 SHA**，不是本轮下载 GB 权重后算出的实测文件哈希。

| 对象 | 官方大小／对象 SHA | 本轮能证明什么 |
|---|---|---|
| E4B `gemma-4-E4B-it-gpu.litertlm` | 精确 2,969,059,328 B；`4912bb5a9c30993c51a7711f763212077458529312175df0573a78323a2bb7ff` | 当前列表与 raw LFS 指针可见；文件名本身不证明 MTP 或全部多模态 section 存在 |
| E4B `gemma-4-E4B-it.litertlm` | 文件页约 3.66 GB；`0b2a8980ce155fd97673d8e820b4d29d9c7d99b8fa6806f425d969b145bd52e0` | README 的 GPU＋MTP 示例明确使用这个基础包；本轮未取得精确 byte size 或内部 section 清单 |
| E2B 旧 SM8750，2026-04-29 替换版 | 3,016,294,400 B；`41dd675fbe735b6029012b5576a5716bac614fd8156de0128db4c9dff3cebd4e` | 固定历史存在；不能当当前 main 的包 |
| E2B SM8750，2026-10-19 重新上传版 | 2,724,793,461 B；`248e732911222c173d6c7d7086258990fc009f23a6144fb8abcf43dd111c7a1b` | 同日上传后又在 main 删除，不能与 4 月包混用身份 |
| E2B `gemma-4-E2B-it_NPU_Uncompiled.litertlm` | 文件页约 2.61 GB；`b4f86de05f54bda24e8633ef20375b81b3fcc5dace7c6ac9f4269644267ca4aa` | 官方描述为供后续 NPU 编译的原包；不等于现成 SM8750 context binary |
| E2B `gemma-4-E2B-it_Qualcomm_QCS8275.litertlm` | 卡片 2,722,352,245 B；`794339191f0e1dc8353b7f84fb205af5e62870ed5647a315eddbf7a9a9c90f06` | 目标为 QCS8275／Hexagon v75／Linux 示例，不得替作 SM8750／v79／Android |

直接来源：[E4B 当前列表](https://huggingface.co/litert-community/gemma-4-E4B-it-litert-lm/tree/main)、[E4B GPU 原始指针](https://huggingface.co/litert-community/gemma-4-E4B-it-litert-lm/raw/main/gemma-4-E4B-it-gpu.litertlm)、[E4B 基础包文件页](https://huggingface.co/litert-community/gemma-4-E4B-it-litert-lm/blob/main/gemma-4-E4B-it.litertlm)、[E2B 当前列表](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm/tree/main)、[未编译包文件页](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm/blob/main/gemma-4-E2B-it_NPU_Uncompiled.litertlm)、[E2B 模型卡的 QCS8275 专节](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm/blob/main/README.md)。

固定 HF head 的页面入口：[E4B head](https://huggingface.co/litert-community/gemma-4-E4B-it-litert-lm/commit/71064b01bd5e2bfd9a5f9dd52df86ae4800138c1)、[E2B head](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm/commit/3d48132a00cf76de57d926de30f5c5c5ed9b8c0d)。本轮模型 raw 指针与 main 列表并非原子读取；部署前必须在最终选定 revision 上重新绑定指针并实测整文件 SHA。

### SM8750 的差异已能解释

官方历史给出三条可固定的证据：

- 2026-04-29，commit `84b6978eff6e4eea02825bc2ee4ea48579f13109` 将旧文件换成 3,016,294,400 B、SHA 41dd675f… 的版本。[替换 diff](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm/commit/84b6978eff6e4eea02825bc2ee4ea48579f13109)。
- 2026-10-19，commit `f06ffc3bd3aa7d1dce244a5db08d42d3a2d81827` 重新上传同名文件，实际变为 2,724,793,461 B、SHA 248e7329…。[上传 diff](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm/commit/f06ffc3bd3aa7d1dce244a5db08d42d3a2d81827)。
- 同日 commit `21c646194210256750db12cfa1e4fdf22bd3ddf1` 明确删除上述 2.724 GB 指针。[删除 diff](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm/commit/21c646194210256750db12cfa1e4fdf22bd3ddf1)。日期／顺序见[官方提交历史](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm/commits/main)。

所以，可陈述“该 SM8750 文件在历史中存在，后来从 main 删除；旧缓存和当前列表对应不同版本”。不可陈述“从未有 SM8750 支持”，也不可反向陈述“找到历史指针就已经可以部署”。本轮没有验证历史大对象能否完整下载、其 SDK 元数据或其在当前设备上的行为。

## 5. 官方 SM8750 示例不能直接充当 v0.19.1 兼容性证明

固定 sample README 确实写 Snapdragon 8 Elite／SM8750、预编译 NPU 包和 NPU→GPU→CPU。进一步读代码后有四项限定：

| 细节 | 固定源码所示 | 对实验的影响 |
|---|---|---|
| LiteRT-LM 依赖 | `gradle/libs.versions.toml` 是 `0.11.0-rc1` | 不能称 sample 已验证 v0.19.1 |
| QNN 获取版本 | 脚本默认 QAIRT `2.44.0.260225`，HTP v79 | 不等于每个历史或新编译包都与此版本匹配 |
| fallback 实现 | App 逐个尝试后端，初始化异常后再建下一后端 engine | 回答成功不能独立证明 NPU；必须记实际后端与原生加速证据 |
| 多模态 executor | NPU 路径的 vision 用 NPU；audio 代码选择 CPU；非 NPU 的 vision 也选 CPU | README 的“多模态 NPU 聊天”不能解释成所有 encoder 和 decoder 均在 NPU |

来源：[固定 README](https://github.com/google-ai-edge/litert-samples/blob/163222b0a76d2e80f959c1fc1f1918420e3b1e4d/samples/litert/qualcomm/llm_chatbot_npu/README.md)、[版本表](https://github.com/google-ai-edge/litert-samples/blob/163222b0a76d2e80f959c1fc1f1918420e3b1e4d/samples/litert/qualcomm/llm_chatbot_npu/gradle/libs.versions.toml)、[QNN 获取脚本](https://github.com/google-ai-edge/litert-samples/blob/163222b0a76d2e80f959c1fc1f1918420e3b1e4d/samples/litert/qualcomm/llm_chatbot_npu/fetch_qualcomm_library.sh)、[LiteRTLMManager](https://github.com/google-ai-edge/litert-samples/blob/163222b0a76d2e80f959c1fc1f1918420e3b1e4d/samples/litert/qualcomm/llm_chatbot_npu/app/src/main/java/com/example/qnn_litertlm_gemma/LiteRTLMManager.kt)。

新 NPU 候选至少要冻结：SM8750／HTP v79、Android arm64 ABI、模型 revision／SHA、编译 QAIRT 版本、LiteRT-LM native ABI、Qualcomm dispatch 版本、QNN HTP／System／v79 Stub／Skel 库、上下文与 KV 的编译约束，以及各模态 executor 的实际后端。当前 sample 中的预置库名称和 README 示例路径不是这一完整组合的验证回执。

QCS8275 卡片明确使用 Linux 环境、v75、QAIRT 2.50.0.260828 与其匹配的 native-v0.18.0-e 示例 runtime；这些条目不能迁移成 SM8750 所需版本。NPU 编译上下文也不能因为运行时传入更大 maxNumTokens 就视为扩容成功。[QCS8275 卡片](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm/blob/main/README.md)。

另一个格式边界：sample 的 compile_npu.py 处理独立 TFL3 `.tflite` 图，而 `.litertlm` 是 RTLM 多组件容器。该指南没有给出“对整个 NPU_Uncompiled.litertlm 直接运行同一脚本即可得到可用 SM8750 包”的保证。需要官方受支持的 bundle 拆分／编译／重新封装及元数据合同，不能改后缀或把 QCS context 塞进 SM8750 名称。[编译指南](https://github.com/google-ai-edge/litert-samples/blob/163222b0a76d2e80f959c1fc1f1918420e3b1e4d/samples/litert/qualcomm/llm_chatbot_npu/NPU_COMPILATION_GUIDE.md)。

## 6. E4B GPU／MTP 与 E2B NPU 的具体后续实验

### 路线 A：E4B 基础包 GPU，先证明接口与证据链

推荐首个候选明确使用当前基础包 `gemma-4-E4B-it.litertlm`，因为固定 README 的 MTP 示例使用它。2.97 GB 的 `-gpu` 文件可作为另一独立候选；在读取其模型 section／ModelInfo、确认 drafter／多模态组件并完成加载检查前，不把基础包的能力或表格外推给它。[固定运行时 README](https://github.com/google-ai-edge/LiteRT-LM/blob/7a03724cece417f1724c923b3d527b4319730841/README.md)；[E4B 官方模型卡](https://huggingface.co/litert-community/gemma-4-E4B-it-litert-lm/blob/main/README.md)。

候选步骤建议：

1. 独立实现并编译 v0.19.1 native adapter，冻结实际 Android 包、C ABI、LLGuidance 构建能力和原始输出观察点。
2. 先做相同 bundle、GPU、上下文、输入与动作合同的 MTP OFF／ON 对照。新接口优先使用 SpeculativeDecodingConfig；Kotlin engine 的默认模式为 OFF，ON／ADAPTIVE 会加载 drafter，不能只观察配置布尔值就声称实际启用。[EngineConfig](https://github.com/google-ai-edge/LiteRT-LM/blob/7a03724cece417f1724c923b3d527b4319730841/kotlin/java/com/google/ai/edge/litertlm/Config.kt)；[C++ engine settings](https://github.com/google-ai-edge/LiteRT-LM/blob/7a03724cece417f1724c923b3d527b4319730841/runtime/engine/engine_settings.h)。
3. 同一版本控制器保持原目标断言，先执行原诊断任务，再完整 core9，并验证普通中文 Start、后台运行、Stop、idle 重启、新任务不会继承旧动作。原 UI、模型输出和动作绑定不放宽。
4. 分开记录完整任务耗时、冷 engine 创建、warm 每步、prefill／decode／TTFT、约束编译与掩码成本、MTP 实际 acceptance（运行时有指标时）、Current HAL、内存、取消到终态时延和真实 GPU 证据。

MTP 的候选收益是减少某些 decode 时间；短工具输出、严格动态枚举、中文 UI 字符串、draft 接受率和约束开销可能改变收益，必须实测。官方 S26 或其他设备数据不能当作本机 Snapdragon 8 Elite 的数字。不同量化容器、不同 runtime、模板或 sampler 的比较也不能解释为单纯 GPU 对 NPU 的因果速度比较。

### 路线 B：E2B SM8750 NPU，先补齐可部署身份

优先取得一个官方现行支持的 SM8750 bundle 与匹配 runtime；若只能使用历史 commit，则明确标记历史实验，并先确认该具体对象完整性、QAIRT 元数据和固定上下文。若走 NPU_Uncompiled，则先确认完整编译封装路径和组件能力，再生成新的不可变候选。

初次后端诊断要求明确失败而非隐藏 fallback；若实验允许 fallback，必须把每种实际后端独立记分。正向 NPU 证据要覆盖目标 decoder，视觉／音频组件另列。仅打印 backend=NPU 或成功返回文本不够。NPU 上的 MTP、动态逐步约束及取消稳定性在本轮都没有实测依据，不做肯定结论。

两条路线都不改变当前已冻结 Hepta 版本和正在进行的测试。新运行时会改变 native／receipt／collector 合同，必须有独立 source／APK／candidate 身份，不把新后端测量并入旧版结果。

## 7. 本轮实际核验与尚未核验

已核验：

- 官方 v0.19.1 发布元数据及 tag→commit，固定源码中的 C ABI、消息角色、约束、取消及生命周期相关实现。
- 官方 SM8750 示例的实际旧依赖、QAIRT 默认、fallback 和模态后端选择。
- 官方 HF 模型列表、可访问的 LFS 指针／对象 SHA、三个固定 SM8750 历史变更。
- 本附件保存时重新计算获取到的 38 份官方 GitHub 文本的 UTF-8 SHA-256，并把 Git blob SHA-1 与 API 返回的 blob 身份逐份比对；完整列表及结果见 `SOURCE-INDEX.json`。这些是源文本身份校验，不是运行时功能测试。

未核验：

- 当前 Android AAR／ELF 是否与这份源码逐字构建一致，以及本设备是否支持所有相应 GPU／NPU 算子。
- 任一 GB 模型对象的完整下载可用性、实测整文件哈希、内部 section／QAIRT 版本及运行内存。
- `-gpu` 文件是否带 MTP drafter、视觉／音频组件，或能否组合到 release 所说的 Artisan 多模态路径。
- 本机速度、温度、能耗、峰值内存、实际模型任务成功率、Stop／重启／普通用户入口。
- 历史 SM8750 模型包在 v0.19.1 和当前 Android 上的兼容性。

许可信息：LiteRT-LM 源文件和 Qualcomm sample 标注 Apache-2.0，当前两份 HF 模型卡也标注 Apache-2.0。Qualcomm SDK／QNN 库的获取和分发另受其自身条款约束，不能从模型卡许可推导可以随意重分发 SDK。[LiteRT-LM 源文件](https://github.com/google-ai-edge/LiteRT-LM/blob/7a03724cece417f1724c923b3d527b4319730841/runtime/conversation/conversation.h)；[sample 许可](https://github.com/google-ai-edge/litert-samples/blob/163222b0a76d2e80f959c1fc1f1918420e3b1e4d/samples/litert/qualcomm/llm_chatbot_npu/README.md)；[E2B 卡片](https://huggingface.co/litert-community/gemma-4-E2B-it-litert-lm/blob/main/README.md)。

本附件可作为下一候选的技术准备依据；它不增加任何现有手机任务的通过数。
