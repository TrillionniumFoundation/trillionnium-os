# 本地模型延迟与同 APK 对照设计

2026-11-10。只读审计建议；没有修改 grammar、模型配置、runtime 或手机。本轮先冻结后台实现，完成真实编译与手机验证。

## 已确认的瓶颈

完整数值、原始路径与 SHA 见同目录 `retained-model-timing-audit.json`。

- Nanbeige v34 / NPU / 4096 / 4 threads 的第 6 次调用：3434 prompt tokens，prefill 18.65 秒，decode 36.37 秒、159 tokens，合计 55.08 秒触发 deadline；JSON 未完成。3946 总预算低于 4096，并非 context overflow。
- 已经是同一 task worker：六请求共一次 hash、SDK init、model create。无需再实现“每步保温”或绕过权重完整性检查；重载不是后五步延迟来源。
- 每请求仍调用 `geniex_llm_reset`。六次 stderr 都是 `past_prompt_tokens size:0 / match_len:0`，因此每步完整 prefill，没有 KV prefix reuse。
- template/tokenize 只耗 20–27 ms。第 4 步起 decode 降至约 4.4 tok/s，但没有温度/频率证据，不能归因热降频或自动 CPU fallback。
- 更严重的是终止错误：第 2 步已进入目标设置页面，之后三次 wait；第 6 步还想进入另一个页面。延长 55 秒或降低 max_tokens 都不能修复此问题。

## 建议顺序

### P1：仅约束 JSON 的无语义空白

稳定后台版本验收后，可单独试验 `DecisionGrammar.java` 的 `prefix/field/comma/ending/root`：禁止 JSON 字符串以外的换行、缩进和可选空格，保留所有字段、原字段次序、96 字 reason、label-first 原始配对、完整 type 文本和所有授权/新鲜度检查。不要修改字符串内容或“压缩”生成后文本来冒充推理加速；模型必须实际少生成这些字符。

历史 Nanbeige step 2–5 分别生成了 31、25、25、25 字节可删除的结构空白。step 1 已是紧凑 JSON。字符数不是 tokenizer token 数，实际节省必须读 native generated_tokens/decode_time，不承诺固定加速比例。这是当前最小、语义风险最低的候选；**本轮不实施，避免打乱已冻结后台源码。**

### P2：把审计元数据与模型需要的权限事实分开投影

`LocalTaskController.prompt()` 当前把 `TaskAuthorization.Frame.evidence()` 全量送给模型，包括两个 SHA256、task_id、discovery_run_id 等。未来可新增专用的 prompt projection；完整 evidence、hash、generation、model-run binding 继续原样存盘并参与真实校验，只从模型文本中省去不参与判断的随机标识。保留 allowed/effective tools、精确 find_query、真实发现结果、已观察 opened_package、success_done_allowed 和方法约束，不能用一段“已完成”摘要代替它们。

不要直接切换回已有 `RecentActionProjection.compactEvents()`：它不等价于当前 readableEvents。它会丢部分参数/结果字段，并在某些路径截断 type_text；当前完整历史是有意保留的语义证据。真正无损的新格式要先逐字段 round-trip 验证 null / false / absent 区别、顺序、标签、完整文字、查询来源与未来新增标量字段，再做模型成功率对照。

### P3：短 reason、终止判定提示只做独立质量实验

Nanbeige step 3/4/5 的 reason 长度为 96/92/88 字符。缩短 reason 可能明显减少 decode，但会改变模型作出动作前的生成过程；不能宣称语义等价。不要同时缩 reason、换采样、换模型，否则无法定位正确性变化。

可检验的通用假设：当前 SYSTEM 要求“确定第一个尚未满足的子目标”，即使目标已满足仍要求构造下一动作。可以单独比较“先判断是否还有未满足目标”的表述，但不能按测试页面硬编码 done。连续同状态 wait 可用通用停滞机制终止为 partial/stalled，不能转写为 success；这只限制浪费，不算业务目标通过。

### P4：KV prefix reuse 留到 runtime 正确性门之后

复用静态 system 前缀有明确收益空间，但不能直接删 reset。[GenieX #1624](https://github.com/qualcomm/GenieX/pull/1624) 修复的是 prefix rollback 失败时重置并完整 prefill；需要先证明当前/候选 SDK 对实际模型可正确 rollback、同前缀与变化后缀无旧状态污染，并保持同任务 generation 与完整输入 ID 证据。不能把已有进程复用误报为 KV 复用。

## Nanbeige 与 Orvena 的对照边界

历史 Orvena v34 / NPU / 8192 的同一普通任务是 open → click → done，三个调用约 19.27 / 14.53 / 15.70 秒，decode 约 12.9–13.6 tok/s；Nanbeige 4096 则发生上述 wait 循环。它们是同 APK/build 和同 system prompt 的保留证据，但不是同 context、同热状态的受控实验，也不是普遍最佳模型排名。Orvena 的历史 task/result.json 仍标记 goal_independently_verified=false；模型报告 done 与独立目标验收必须分开记录。

**采样不能混算：**原始 v34 三个 Orvena 普通任务回执均为 temperature≈.7、top_p≈.8、top_k=40、min_p≈.05，与当前 `native/sampler-profile.inc` 一致；Nanbeige 使用通用 temperature=0、top_p=1、top_k=1。两模型的历史吞吐/终止差异同时包含各自采样与 context 配置，不能视为统一采样的纯模型对照；没有证据表明当前源码改变了历史 Orvena 采样。新 APK 每轮仍须记录 native 实际 sampler，不仅看 UI 模型名，也不能把历史结果算作新 APK 的通过项。

## 同 APK 真机对照的最小流程

1. 先完成后台实现本身验收。固定 APK SHA、build identity、SDK/llama pins、grammar/prompt 版本、backend、threads、任务文本及后台屏幕尺寸；同一任务只能改变预先声明的一个变量。当前两种 profile 的 4096 / 8192 差异按“实际可部署配置对照”报告，不冒充纯模型架构实验。
2. 首轮只对当前 Nanbeige 4096 与 Orvena 8192 做短任务筛选：既有“进入页面并停留”、既有计算器步骤/结果验收、中文备忘录输入及保存回读；要求应用、初始状态、完整指令一致。使用各自明确记录的 sampler，交错顺序，记录开始可用内存与实际热状态；没有热采样则标记未知。
3. 通过者再进入已有完整 core9 与后台链验收。保留每一步真实模型输出、工具调用、前后观察、native phase/profile、精确 prompt tokens、generated tokens、session hash/create/reset 计数、独立目标验证、主屏前后状态与清理证据。优先比较成功率、错误动作和停止正确性，再比较成功任务端到端耗时；不能只比较单 token 峰值。
4. 若之后试 compact JSON：用一个明确包含 baseline/compact 两分支的同 APK，每任务开始固定分支并纳入 prompt/grammar receipt，禁止任务中热切换或失败自动重试。先以保留观察做纯本地决策回放排除格式/标签绑定退化，再用同初始状态真实执行；回放不是端到端通过。不要另装两版 APK 后把性能变化归给模型。
5. 停止门：出现越界/陈旧动作、目标正确性退化、错误 success、主屏受影响或 cleanup_unknown，立即停止该候选，不用更长 timeout、自动替换模型或重放动作来凑通过。有限任务均通过只能说明覆盖的范围，不能称任意 App 全量正确。

## 不需要改的部分

不添加 BOS：实际 Nanbeige GGUF 的 add_bos=true，已用 `llama_tokenize(...,true,true)` 自动补首 token。`formatted-prompt.txt` 缺可见首 `<|im_start|>` 不表示最终输入缺 token。[#1621](https://github.com/qualcomm/GenieX/pull/1621/files) 只修 CLI/server 的思考输出拆分，不是当前 SDK 输入修复。
