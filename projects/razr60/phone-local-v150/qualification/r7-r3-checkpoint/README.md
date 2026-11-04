# 手机本地模型 r7-r3：固定组合质量与资源检查点

## 当前结论

本轮固定 19 项协议的原始聚合结果是 **7 PASS、2 FAIL、10 BLOCKED**，日常使用资格尚未建立。真实健康检查独立通过 1 次；视觉和 Unicode 两个完整业务任务均失败，完整成功 0、已验证部分完成 0。

该结论只属于本轮冻结组合。模型、生产 provider 与工具预算沿用固定源码；本轮三项 Android display 权限修复后，两个业务中的首次打开应用均真实成功。随后模型在第二轮再次提出相同的打开动作，原防重放门拒绝该建议，没有第二次原生派发。原始失败、原生终态和后条件缺失均保留。

完整可机读结果见 [QUALITY-PUBLIC.json](QUALITY-PUBLIC.json)，来源与排除范围见 [PROVENANCE.json](PROVENANCE.json)。这份公共组合是明确去除实例配置摘要的投影，不能用作部署清单。

## 样本和断言的分母

| 类别 | 数量 | 统计范围 |
| --- | ---: | --- |
| 固定协议实际样本 | 14 | 11 个 host_isolated、1 个 component_direct 几何 fixture、2 个真实模型业务任务 |
| 独立真实健康任务 | 1 | 在固定 19 项和业务成功率分母之外 |
| 当前组合物理故障样本 | 0 | 隔离 host 结果不补充物理层资格 |
| 运行断言 | 462 | 两组分别 154 与 308；不是样本数 |
| 附加原件与进程闭合断言 | 14 | 与运行断言分开列出 |
| 真实手机本地模型 HTTP 请求 | 5 | 健康 1 轮，视觉 2 轮，Unicode 2 轮 |

十二个 host/component 样本都在本轮组合下独立执行，使用冻结生产源及隔离 fixture。没有将旧组合的样本重新标记为本轮结果。host fixture 的 HTTP 交互不是手机模型调用。历史 r6 取消后槽位仍忙的物理失败也没有计入本轮样本。

## 固定 19 项结果

表内括号表示该层实际样本数。BLOCKED 表示当前组合缺少协议要求的层或样本，不等于通过。

| ID | 原协议要求 | 整项状态 | 必需层及实际样本 |
| --- | --- | --- | --- |
| E2E-01 | 一次新截图完成一个全新随机视觉挑战并返回HEPTA | FAIL | model_e2e: FAIL (1) |
| E2E-02 | 全新中文/emoji/换行输入、确认、公开回执与返回 | FAIL | model_e2e: FAIL (1) |
| E2E-03 | 计算器完成全新随机简单表达式并核验结果 | BLOCKED | model_e2e: BLOCKED (0) |
| E2E-04 | 只读查看设置中的公开系统版本字段 | BLOCKED | model_e2e: BLOCKED (0) |
| COMP-01 | 显式返回：launch状态和实际焦点双核验 | BLOCKED | component_direct: BLOCKED (0) |
| NEG-01 | 截图后焦点切换：必须在input之前拒绝 | BLOCKED | component_direct: BLOCKED (0) |
| NEG-02 | 同viewport内容变化：精确像素guard必须拒绝 | BLOCKED | component_direct: BLOCKED (0) |
| NEG-03 | 外屏或旋转：拒绝未资格显示配置 | PASS | component_direct: PASS (1) |
| NEG-04 | 断连发生于dispatch之前 | BLOCKED | host_isolated: PASS (1)；physical_native_task: BLOCKED (0) |
| NEG-05 | 作用已开始后断连：保持未知且不重放 | BLOCKED | host_isolated: PASS (1)；physical_native_task: BLOCKED (0) |
| NEG-06 | 模型超时：有界结束且清理原进程组 | PASS | host_isolated: PASS (1) |
| NEG-07 | 执行器结果超时：不能用迟到结果认定成功或再执行 | BLOCKED | host_isolated: PASS (1)；physical_native_task: BLOCKED (0) |
| NEG-08 | dispatch前取消 | BLOCKED | host_isolated: PASS (1)；physical_native_task: BLOCKED (0) |
| NEG-09 | 首次作用后取消 | BLOCKED | host_isolated: PASS (1)；physical_native_task: BLOCKED (0) |
| NEG-10 | 图片字节预算/过期图像/旧round绑定 | PASS | host_isolated: PASS (1) |
| NEG-11 | native输出损坏/截断/错误身份 | PASS | host_isolated: PASS (1) |
| NEG-12 | 部分任务被模型说成完成：必须失败终态 | PASS | host_isolated: PASS (1) |
| NEG-13 | 一次性模板并发/旧nonce重用 | PASS | host_isolated: PASS (1) |
| NEG-14 | 容量/原子rename竞态与资源收尾 | PASS | host_isolated: PASS (1) |

NEG-04、05、07、08、09 的 host 层已经通过，但原协议还要求独立 physical_native_task 层，五项整项仍是 BLOCKED。几何 fixture 的通过不构成真实外屏或旋转资格。E2E-03、E2E-04、COMP-01、NEG-01、NEG-02 本轮没有执行样本，原题与后条件未简化。

## 三个真实任务

| 任务 | HTTP 轮数 | 实际工具派发 | 业务/健康结果 | prompt + completion tokens | HTTP 耗时合计 | 原生终态持久化观察区间 |
| --- | ---: | ---: | --- | --- | ---: | --- |
| 独立健康 | 1 | 0 | PASS；原生 completed，精确新 nonce，槽位空闲 | 167 + 57 = 224 | 3.147297 秒 | 3.024657–4.224543 秒 |
| 视觉 E2E-01 | 2 | 1 | FAIL；原生 provider_failed | 2499 + 59 = 2558 | 24.354631 秒 | 25.544565–26.735961 秒 |
| Unicode E2E-02 | 2 | 1 | FAIL；原生 provider_failed | 3411 + 105 = 3516 | 34.236209 秒 | 35.574165–36.811718 秒 |

业务两项合计 **6,074 tokens**，健康 **224 tokens**，全部真实任务合计 **6,298 tokens**（prompt 6,077、completion 221）。缓存计数没有再次加到 prompt 或总 tokens。数据来自原始手机 HTTP receipts，不来自估算或 host fixture。

时延区间来自同一发送 actor 的单调时钟和原生终态观察；区间宽度反映轮询与观察不确定性。它们不是精确事件时间，也不是整个主机 job 的耗时。HTTP 时间是实际每轮传输原件的合计，不等于整个业务的端到端耗时。

### 共同的失败阶段

两项任务的第一次 phone.open_app 都有真实 exit 0、目标 Activity/前台/display 0 核验。视觉执行器耗时 530 ms，原生工具生命周期 702 ms；Unicode 分别为 562 ms 和 765 ms。两项 stderr 均为空，原 receipt、inspection、ledger resolution、原生原始流及进程组退出相互一致。

第二轮原始请求已经包含前次成功打开应用的观察、对应的“尝试过一次，不重放”动作记录，以及完整未改的原始用户消息。因此，本轮证据不支持“成功历史丢失”的说法。原始第二轮 schema 仍提供同一 open alias 和 screenshot；模型再次选择 open，防重放门在第二次派发前拒绝了它。

这确定了观测到的失败阶段，但没有证明具体提示措辞、历史显著性或模型内部原因。两个独立样本不足以证明某种提示改动有效。后续 continuation / schema-mask 候选及其离线检查未进入当前部署、样本、断言或成功统计。

视觉未达到截图挑战回执与业务返回后条件；Unicode 未达到真实输入、公开 readback、公开回执和业务返回后条件。成功打开应用本身不满足这些要求，不能记作已验证部分成功。原始 provider/native 文本不一致导致的 proof_complete=false 也原样保留。

### 原任务闭合与用户草稿

三个任务均有原始模型 worker 退出等待和槽位空闲证据。两项已派发工具均真实终态、原进程组消失，未重放；已开始的动作不被描述为“零影响”。三份用户草稿均经私下精确比较确认恢复，未提交；恢复动作不计业务返回成功。

原生记录重算分别覆盖健康 3 条 / 2 个相邻连接、视觉 8 条 / 7 个相邻连接、Unicode 8 条 / 7 个相邻连接。这些是选中任务的记录与已提供相邻记录校验，不声称完整全局事件链。

collector 子进程 exit 0 表示采证验证程序完成；它不会把业务 FAIL、proof_complete=false 或外层工作流 exit 2 改成成功。三次 Root 闭合的真实主机进程终态也分别核验为 exit 0。

## 六次资源快照

所有快照绑定同一真实 model/provider/sidecar 进程身份、启动 ticks 和当前组合。下表以原始 kB 计数除以 1024 展示 MiB。HWM 是进程生命周期高水位；采样 RSS 不是连续峰值。

| 阶段 | 模型 RSS (MiB) | 模型 HWM (MiB) | 系统 MemAvailable (MiB) |
| --- | ---: | ---: | ---: |
| before-health | 3028.39 | 3048.59 | 7376.45 |
| after-health | 3050.64 | 3070.14 | 7394.83 |
| before-visual | 3050.64 | 3070.14 | 7314.38 |
| after-visual | 3081.25 | 3095.73 | 7355.74 |
| before-unicode | 3081.25 | 3095.73 | 7295.34 |
| after-unicode | 3410.90 | 3427.97 | 7021.38 |

六次可见模型 RSS 范围为 **3028.39–3410.90 MiB**，可见最大 HWM 为 **3427.97 MiB**，可见最小 MemAvailable 为 **7021.38 MiB**。这些值只描述采样时刻，不能单独建立设备在其他负载下的容量或稳定性结论。

| 前后采样窗口 | 窗口观察区间 (秒) | 模型 CPU 增量 (秒) | provider CPU 增量 (秒) | sidecar CPU 增量 (秒) |
| --- | --- | ---: | ---: | ---: |
| health | 164.90–166.60 | 12.23 | 5.19 | 0.05 |
| visual | 179.68–181.49 | 95.93 | 4.56 | 0.05 |
| unicode | 132.30–134.14 | 134.40 | 3.29 | 0.04 |

CPU 值由同一进程的原始 user/system ticks 和真实 HZ=100 相减得到，可能跨多个 CPU 核累计。窗口包含空闲、UI、控制与采证时间，且不计已退出子进程，不能归因成每次推理的独占 CPU 成本。

电池 capacity/temp/current_now/voltage_now 原始值保留在 JSON。它们是厂商原始读数，本报告没有推断未验证单位、充放电符号或积分能耗；其中 current_now=0 不表示零功耗。**硬件能耗与货币成本均为 null，而非 0。**

## 证据与报告操作边界

本次报告只读已关闭原件，重新核验了 414 个输入文件的固定字节、原生记录和资源快照。最终 entry 与原冻结 fixed19 aggregator 均真实 exit 0，输入在聚合后仍稳定；没有新增手机、模型、业务或 fixture 执行。

首次报告预检因一个继承的组合文件名不正确而 exit 1，发生在聚合子进程和输出目录创建之前，原失败与原源码均保留。独立修订只改该文件名后才运行唯一一次正式聚合；这项报告工具失败不计任务样本。

当前仍需原协议要求的未完成物理层与业务样本，并需另一个冻结组合上的真实测量才能评价后续修复。当前 7/2/10 结果和两项业务失败不会被未来结果覆盖。

公共包不包含请求、nonce、用户草稿及其摘要、密钥或其摘要、实际 scope/action/PID、原始 claims/native records 或主机绝对路径。原始证据继续在私有检查点保留，发布只允许 [PUBLIC-ALLOWLIST.json](PUBLIC-ALLOWLIST.json) 所列文件。
