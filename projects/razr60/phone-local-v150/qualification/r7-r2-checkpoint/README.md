# 手机本地执行组合 v150-r7-r2：质量与资源检查点

**本组合的辅助健康请求 1/1 通过；真实手机业务 0/2 完整成功、0/2 验证部分成功、2/2 失败。固定 19 项的严格聚合结果为 7 PASS、2 FAIL、10 BLOCKED，尚未取得日常使用资格。**

本报告只计入完整组合摘要 `ee2bba801325525f9fa910c2c613352b54c32cb71921f2e7a16d2f25205e94d4` 的新实测。原 19 项、预算、后条件和分层门槛保持不变。统计原件来自两组新主机验证、三条真实手机请求、六次只读资源采样及独立闭合记录；完整公开数值见 [QUALITY-SUMMARY.json](QUALITY-SUMMARY.json)，来源绑定见 [PROVENANCE.json](PROVENANCE.json)。

## 结果与分母

| 类别 | 当前样本数 | 本轮结果 | 统计边界 |
| --- | ---: | --- | --- |
| 真实模型业务 | 2 | 2 失败，0 完整成功，0 验证部分成功 | E2E-01、E2E-02 |
| 隔离主机验证 | 11 | 各自的负向协议条件通过 | 使用冻结生产源码与实际 HTTP worker；不是手机或真实模型样本 |
| 几何组件验证 | 1 | 拒绝条件通过 | NEG-03 的 component_direct fixture，不代表外屏或旋转支持 |
| 固定 19 中已执行样本 | 14 | 由原聚合器按各层条件判定 | 上述 2 + 11 + 1，不等于 14 个案例通过 |
| 辅助真实健康 | 1 | PASS | 独立于固定 19 和业务成功率 |
| 当前物理负向样本 | 0 | 缺失 | 五项双层案例仍有物理门槛 |

12 个主机/几何样本均在本组合下重新执行，保留各自原行和终态，不把旧组合的样本重新归组。**462 条运行断言与 14 条导出/进程闭合断言分别记录；它们不是样本量。** 负向验证中任务按预期失败、取消或保持不确定，可以满足该负向案例的条件，不能计作模型业务成功。

当前业务成功率为 0/2，仅描述这两条有界新样本；它不是稳定性或长期成功率估计。辅助健康通过说明新指令、唯一模型请求、真实原生终态与清理链路成立，不能代替视觉或文本业务完成。

## 三条真实请求的原始耗时和用量

| 请求 | 结果 | Prompt / Completion / Total tokens | HTTP 耗时（秒） | 原生终态持久化观察区间（秒） | 手机工具分派数 |
| --- | --- | ---: | ---: | ---: | ---: |
| 健康（辅助） | PASS | 172 / 58 / 230 | 3.226108 | 3.011533–4.206784 | 0 |
| E2E-01 视觉 | FAIL | 1123 / 28 / 1151 | 12.103802 | 12.765552–13.952773 | 1 |
| E2E-02 Unicode | FAIL | 1569 / 32 / 1601 | 15.310555 | 15.720707–16.872234 | 1 |

业务两条合计 **2,752 tokens**；辅助健康 **230 tokens**；三条真实请求合计 **2,982 tokens**，其中 prompt 2,864、completion 118。缓存 token 是 prompt 的子集，未再叠加到总量。主机 fixture 的合成响应不进入真实模型用量。

每条请求只分派一次模型 HTTP 请求，没有自动重试或云模型回退。HTTP 耗时来自原始请求回执。原生终态区间来自同一发送 actor 的单调时钟：它是观察界限，**不是精确的原生事件耗时，也不是 Main/Pocket4 作业持续时间**。两条失败业务在首次工具调用退出后结束，这些耗时不能当作完成视觉或 Unicode 全流程的耗时。

## 两项业务为什么失败

两条模型决策均生成一次合法的 `mobile_use open`，映射到真实 `phone.open_app`。各有一次原生工具分派；视觉的执行器耗时 65 ms、原生工具耗时 272 ms，Unicode 分别为 52 ms、239 ms。两者原始退出码均为 **68**，28 字节 stderr 均报告 `Can't find service: display`。

原件证明工作进程已进入执行入口（`effect_started=true`），随后以非零状态结束。每个原工作进程均已真实 wait/join，原进程组不存在；原回执、独立检查与追加的 ledger resolution 对应同一动作，未重放。这里 `sidecar state=completed` 表示执行器进程完成，退出码 68 仍表示命令失败。

没有完成截图、视觉坐标选择/点击、Unicode 输入、公开原文读回或业务要求的返回。两条原 native 任务均保持 `provider_failed`，业务后条件缺失，`proof_complete=false`。原 provider/native 错误文本不完全一致也原样保留。独立清理、原稿精确恢复和原动作已收尾均不升级为业务成功；原稿恢复不计作业务返回。

本报告只把错误定位到“原工作进程找不到 Android display service”这一可见边界。是否由某个 SELinux 规则、服务发现或其他运行条件造成，需要独立原件确认；本报告不凭错误字符串断言具体策略修改，也不宣称动作零效果。

## 固定 19 项逐项状态

| 案例 | 当前状态 | 已执行样本 | 必需层与当前结果（样本数） |
| --- | --- | ---: | --- |
| E2E-01 | FAIL | 1 | model_e2e: FAIL（1） |
| E2E-02 | FAIL | 1 | model_e2e: FAIL（1） |
| E2E-03 | BLOCKED | 0 | model_e2e: BLOCKED（0） |
| E2E-04 | BLOCKED | 0 | model_e2e: BLOCKED（0） |
| COMP-01 | BLOCKED | 0 | component_direct: BLOCKED（0） |
| NEG-01 | BLOCKED | 0 | component_direct: BLOCKED（0） |
| NEG-02 | BLOCKED | 0 | component_direct: BLOCKED（0） |
| NEG-03 | PASS | 1 | component_direct: PASS（1） |
| NEG-04 | BLOCKED | 1 | host_isolated: PASS（1）；physical_native_task: BLOCKED（0） |
| NEG-05 | BLOCKED | 1 | host_isolated: PASS（1）；physical_native_task: BLOCKED（0） |
| NEG-06 | PASS | 1 | host_isolated: PASS（1） |
| NEG-07 | BLOCKED | 1 | host_isolated: PASS（1）；physical_native_task: BLOCKED（0） |
| NEG-08 | BLOCKED | 1 | host_isolated: PASS（1）；physical_native_task: BLOCKED（0） |
| NEG-09 | BLOCKED | 1 | host_isolated: PASS（1）；physical_native_task: BLOCKED（0） |
| NEG-10 | PASS | 1 | host_isolated: PASS（1） |
| NEG-11 | PASS | 1 | host_isolated: PASS（1） |
| NEG-12 | PASS | 1 | host_isolated: PASS（1） |
| NEG-13 | PASS | 1 | host_isolated: PASS（1） |
| NEG-14 | PASS | 1 | host_isolated: PASS（1） |

NEG-04/05/07/08/09 的隔离主机层已经通过，但各自 `physical_native_task` 仍无当前样本，因此整体为 BLOCKED。历史 r6-r2 的取消请求曾真实 cancelled、但 slot 仍 busy 并导致服务停止；该失败原件保留为历史，不计作当前 r7-r2 的物理样本。E2E-03/E2E-04、COMP-01、NEG-01/NEG-02 也没有当前组合的可用独立样本。

## 资源实测

六次采样均绑定相同当前角色的 PID/进程组/session/start ticks、实际可执行文件与上下文，并复算原只读数据。下表使用 Linux 报告的 kB 作为 KiB 换算；GiB = kB / 1,048,576，MiB = kB / 1,024。公开版本省略实际进程标识。

| 采样阶段 | 模型 RSS（GiB） | 模型 HWM（GiB） | Provider RSS（MiB） | Sidecar RSS（MiB） | 系统 MemAvailable（GiB） |
| --- | ---: | ---: | ---: | ---: | ---: |
| before-health | 2.9569 | 2.9770 | 26.33 | 3.95 | 7.2144 |
| after-health | 2.9819 | 2.9972 | 28.08 | 3.95 | 7.1794 |
| before-visual | 2.9819 | 2.9972 | 28.08 | 3.95 | 7.2087 |
| after-visual | 3.0088 | 3.0229 | 28.08 | 3.95 | 7.1250 |
| before-unicode | 3.0088 | 3.0229 | 28.08 | 3.95 | 7.1435 |
| after-unicode | 3.1301 | 3.1469 | 28.08 | 3.95 | 7.0188 |

本次六个快照中，模型 RSS 为 **2.9569–3.1301 GiB**，最高 HWM 为 **3.1469 GiB**；最低 MemAvailable 为 **7.0188 GiB**。RSS 是瞬时快照，HWM 是该进程整个生存期的高水位，不是单次推理独占峰值。

| 任务对应的采样窗口 | 观察间隔范围（秒） | 模型 CPU 增量（秒） | Provider CPU 增量（秒） | Sidecar 父进程 CPU 增量（秒） |
| --- | ---: | ---: | ---: | ---: |
| health | 107.50–109.16 | 12.55 | 3.13 | 0.02 |
| visual | 133.36–135.04 | 47.70 | 3.66 | 0.03 |
| unicode | 74.50–76.26 | 60.18 | 1.72 | 0.01 |

CPU 增量由同一进程的原始 ticks 差值除以实际 HZ=100 得出。上述窗口明显宽于模型请求，包含 UI、控制、等待和采证开销；它们不能归因成某次推理的精确 CPU 成本，且不包含已退出的执行器子进程。

电池原始 capacity 六次均为 97，temp 原值从 280 到 290，current_now 原值均为 0，voltage_now 原值为 4,384,000–4,390,000。保留厂商原始量纲，不将 current_now=0 或电量未跳变解释成零功率。**能耗（焦耳）与货币成本均为 null/未测定**，没有用 token 数估算硬件电费或宣称本地运行成本为零。

## 证据闭合与报告生成

健康、视觉、Unicode 分别独立核验 3、7、7 条选定原生记录，以及 2、6、6 条已观察到的相邻全局前驱链接。三者都仅证明所提供选定记录的完整性；未读取的全局 WAL 链不在该证明范围内。

三条任务均已由 Root 独立核查采证 actor/phone 退出码、collector 实际退出码、模型 worker join/slot idle、原动作终态和私有原稿精确恢复。三次原稿恢复均未提交原稿，不产生业务成功 credit。原始任务、claim、回执及失败文本保持不变。

总报告只读核验 **373 个输入文件**。报告入口、冻结聚合器实际进程均返回 0，最终聚合仅执行一次。此前一次报告准备过程因同一 actor 时钟的两个说明标签文字不同而退出 1，发生在创建聚合输出之前；新报告源仅接受已冻结 sender 使用的两个准确标签，仍严格核对相同起止纳秒、scope、原请求与一次 Send。该失败源和日志完整保留，没有重跑任何手机请求或 fixture。

公开 JSON 是独立明确投影：去除实例配置摘要，保留原报告 SHA 与投影来源；不包含完整请求、nonce、原稿或其摘要、密钥、原始 claim/native 记录、实际 scope/action/process 标识或主机绝对路径。原内部报告与全部私有证据未改写。

## 后续资格边界

后续修复应使用新的独立组合与新请求，不能重放本轮的原请求或动作。本轮没有证明视觉或 Unicode 完整业务能力，也没有证明外屏、旋转、折叠或一般 App 范围。必须继续按原 19 项与原预算完成缺失物理层和业务样本，并积累重复的代表性业务结果后，才能评价日常使用可靠性。
