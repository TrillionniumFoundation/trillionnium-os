# RAZR60 本机小模型：r7-r1 固定组合质量检查点

**本组合已通过一次严格的手机本地模型健康请求；当前两项真实手机业务均失败，尚不具备日常使用资格。** 固定 19 项协议保留全部项目，实际冻结聚合结果为 **7 PASS、2 FAIL、10 BLOCKED**。

这里只统计已经运行并关闭原件的 r7-r1 完整组合。历史 r6-r2 取消后槽位仍忙的失败保留在原检查点；后续 r7-r2 权限或模块修改属于新组合，不纳入这里。原请求、原文本和原动作没有重放。

完整机器可读结果见 [QUALITY-PUBLIC.json](actual-01/QUALITY-PUBLIC.json)。精确公开范围见 [PUBLICATION-ALLOWLIST.json](PUBLICATION-ALLOWLIST.json)，出处与实际聚合终态见 [PUBLIC-CHECKPOINT-MANIFEST.json](PUBLIC-CHECKPOINT-MANIFEST.json)。

## 样本量与统计边界

| 类别 | 样本量 | 本次结果 | 证据范围 |
| --- | ---: | --- | --- |
| 真实模型业务任务 | 2 | 完整成功 0、已验证部分完成 0、失败 2、取消 0、未确认 0 | 视觉、Unicode 各一次，均在首个应用操作超时 |
| 独立真实健康请求 | 1 | PASS 1 | 新 nonce 原样返回；语法没有写死答案；native completed、0 工具、HTTP worker 回收、槽位空闲 |
| 主机隔离负向样本 | 11 | 所在层全部 PASS | 冻结原源码的超时、断连、取消、一次性身份、预算与证据守卫 |
| 几何组件样本 | 1 | 所在层 PASS | 冻结原函数对不合格显示身份、旋转和几何数据的拒绝 |
| r7-r1 实机负向样本 | 0 | 尚未运行 | 五个双层故障项目的实机层仍 BLOCKED |

固定集共有 **14 个已执行样本**：2 个真实业务、11 个主机隔离样本、1 个几何组件样本。健康在固定集之外单列。检查包含 **462 项运行断言和额外 14 项原件/进程闭合断言**；这 476 项检查不是 476 个独立任务。

当前业务完整成功为 **0/2**。这是这两个任务的观测结果，不能估计一般手机操作的可靠率。负向合成任务按预期失败或取消，可以使其守卫项目通过，但不等于真实手机业务成功。

## 三条真实请求

| 请求 | 原始任务终态 | HTTP 耗时 | prompt / completion / total tokens | native 终态观测区间 | 原工具 |
| --- | --- | ---: | ---: | --- | --- |
| 独立健康 | completed，健康 PASS | 3.607 s | 169 / 76 / 245 | 3.038–4.237 s | 0 |
| E2E-01 视觉挑战 | provider_failed，业务 FAIL | 12.182 s | 1124 / 27 / 1151 | 72.303–73.551 s | 1 个 open_app；sidecar 60.011 s 超时 |
| E2E-02 Unicode | provider_failed，业务 FAIL | 15.327 s | 1562 / 46 / 1608 | 75.444–76.676 s | 1 个 open_app；sidecar 60.024 s 超时 |

区间来自原 Send 与原 native 终态的有界观察，宽度分别约 1.199、1.248、1.232 秒。上端点是终态观察上界，不是精确的原生事件持久化时刻。原 collector 的单值 native 端到端时延仍为 null，未用推算值填补。

两项业务共 **2686 prompt + 73 completion = 2759 tokens**。加入健康，共 **2855 + 149 = 3004 tokens，3 次真实模型请求**。使用量来自原手机 HTTP 回执；主机 HTTP fixture 不计为模型使用量。每条真实任务只有一次原始模型请求，无隐藏重试或云端回退。

### 两项业务的准确失败位置

两个响应都符合新的 named-action 格式，分别选择了正确注册别名“视觉挑战”和“Unicode验证”，经过受控 phone.open_app 映射后各进入原 native 执行链一次。本轮首个动作的结构与应用选择因此有证据成立。

两个执行器调用都超过既有 60 秒上限。原始 stderr 重复记录 servicemanager.installed 和 servicemanager.ready 属性读取被拒绝，最终 timed_out；native 工具退出码均为 72，耗时分别约 60.222、60.233 秒。模型 HTTP 都正常 stop，原 HTTP worker 已回收、原槽位空闲。

这些原件支持继续检查 Android worker 运行域与系统服务属性访问权限。原脚本没有逐子命令阶段回执，不能仅据 stderr 确定卡在某个 dumpsys 还是 am，也不能断言应用完全没有被启动。effect_started=true 只证明进入实际执行入口，不证明业务成功或零副作用。

两项任务都未进入截图/图像选择、点击或 Unicode 输入。视觉挑战与业务返回未核实；Unicode 的编辑器原文、公开原文、公开业务回执、HEPTA 返回四个后条件全部缺失。没有完整成功，也没有已验证部分业务完成；一次合法模型动作转换不计业务部分完成。

### 原动作与原稿的收尾

两项原 sidecar 回执中的 UID/GID、域、唯一 dispatch、action/command 绑定、waitpid_joined、process_group_absent 均满足严格终态条件。原 ledger inspection/resolution 已读取核对，没有未解动作，也没有重复派发。

这是执行过程安全收尾的证据。原任务仍失败，原 proof_complete=false 不变。provider 错误文本与 native 包装错误文本的差异也保留，未为得到通过而修改。

三条请求之后，用户原草稿均经精确比对恢复，没有提交原草稿。草稿清理不计业务返回，也不计业务恢复成功。本检查点没有独立业务恢复任务，业务恢复成功数为 0。

## 固定 19 项状态

| 项目 | 结果 | 已有层级或缺口 |
| --- | --- | --- |
| E2E-01 新视觉挑战并返回 | FAIL | 首个 open_app 超时，挑战/返回未完成 |
| E2E-02 Unicode 完整任务 | FAIL | 首个 open_app 超时，四个后条件未完成 |
| E2E-03 计算器随机表达式 | BLOCKED | 无本组合真实样本，原题与 7 工具/8 轮预算不变 |
| E2E-04 只读系统版本 | BLOCKED | 无本组合真实样本，需唯一公开字段与独立读回 |
| COMP-01 显式返回 | BLOCKED | 无独立 component_direct 样本，其他任务清理不抵扣 |
| NEG-01 焦点变化 | BLOCKED | 缺本组合真实组件证据 |
| NEG-02 页面内容变化 | BLOCKED | 缺本组合真实组件证据 |
| NEG-03 不合格显示/旋转拒绝 | PASS | 几何组件 fixture；不证明真实外屏支持 |
| NEG-04 dispatch 前断连 | BLOCKED | host PASS，physical_native_task 缺失 |
| NEG-05 作用开始后断连 | BLOCKED | host PASS，physical_native_task 缺失 |
| NEG-06 模型超时 | PASS | 隔离原入口、真实 HTTP worker 与收尾 |
| NEG-07 超时与迟到结果 | BLOCKED | host PASS，physical_native_task 缺失 |
| NEG-08 dispatch 前取消 | BLOCKED | host PASS，本组合无实机样本 |
| NEG-09 原作用后取消 | BLOCKED | host PASS，physical_native_task 缺失 |
| NEG-10 图片预算与旧图绑定 | PASS | 隔离冻结原函数 |
| NEG-11 损坏/错身份 native 输出 | PASS | 隔离冻结原函数 |
| NEG-12 部分完成不能报整项成功 | PASS | 原后条件和终态守卫 |
| NEG-13 一次性模板并发/重用 | PASS | 原 O_EXCL 消费与身份守卫 |
| NEG-14 容量、rename 竞态与收尾 | PASS | 原服务、文件错误与资源闭合 |

五项断连、迟到结果和取消项目保留了实际 fixture HTTP、原 worker/进程组收尾、一次性 claim、独立计数器和不重放证据，但仍需独立物理 native 样本。历史 r6-r2 取消槽位 busy 的实机 FAIL 没有挪到本组合。

## 资源与成本

六次只读采样均核对三角色实际身份、启动时刻、当前组合和采集进程终态。内核 SC_CLK_TCK 实测为 100。单位沿用原 /proc 的 kB。

| 观察点 | 模型 RSS kB | 生命周期 HWM kB | 系统 MemAvailable kB |
| --- | ---: | ---: | ---: |
| 健康前 | 3100676 | 3121604 | 7617392 |
| 健康后 | 3123156 | 3142964 | 7625676 |
| 视觉前 | 3123156 | 3142964 | 7698816 |
| 视觉后 | 3156700 | 3171516 | 7583628 |
| Unicode 前 | 3156700 | 3171516 | 7495780 |
| Unicode 后 | 3286676 | 3301680 | 7355408 |

模型 RSS 约 **2.96–3.13 GiB**，生命周期 HWM 最高约 **3.15 GiB**，系统可用内存最低约 **7.01 GiB**。离散采样不证明请求期间的瞬时峰值；RSS 增长不足以单独判定泄漏，HWM 也不能解释为每请求峰值。

| 观察窗口 | 窗口时长 | 模型 CPU 增量 | provider 增量 | sidecar 父进程增量 |
| --- | --- | ---: | ---: | ---: |
| 健康前后 | 121.640–123.430 s | 14.10 CPU-s | 2.78 CPU-s | 0.02 CPU-s |
| 视觉前后 | 187.730–189.450 s | 48.01 CPU-s | 3.16 CPU-s | 0.20 CPU-s |
| Unicode 前后 | 186.530–188.190 s | 60.21 CPU-s | 3.30 CPU-s | 0.20 CPU-s |

窗口含空闲、编排和采证开销，CPU 增量不归因为任务专属成本。sidecar 数值仅为父进程，未覆盖已退出 worker 后代。多线程累计 CPU 秒也不能直接当作墙钟秒。

电池 vendor 原始值保留：capacity 98；temp 260 至 280；current_now 出现 0、-32000、-221000；voltage_now 4397000 至 4390000。未独立证明字段单位、符号和计费关系，因此能耗焦耳与货币成本均为 **null**。current_now=0 不表示零功耗；无云端回退也不表示零资源成本。

## 原件完整性与实际进程状态

本次报告读取 **208 个命名输入**，核对原始 SHA256 和前后稳定性。原 native 健康 3 条、视觉 7 条、Unicode 9 条记录分别核验哈希和 2、6、8 个相邻链接；不宣称验证了未提供的整个全局 journal。

原 capture actor/phone 进程均为 0，实际业务 collector 子进程也为 0。业务 workflow 的退出 2 和 failed/proof_complete=false 保持原样。视觉的一次重复 host export 被 O_EXCL 拒绝，原完整 archive 已保留，随后只补主机 collector，没有再次采集或发送任务。

冻结 aggregator 本次实际运行退出 0。它证明汇总程序完成，不能替代原任务终态。

## 后续顺序

1. 用独立新组合精确修复并核验 Android 服务属性权限。保留 r7-r1 原失败/回执/claim，不把修复倒贴到本报告。
2. 新组合首先运行全新有界健康请求，再分别执行新视觉与新 Unicode 完整任务。原请求、文本与已发生动作不重放。
3. 按原协议补 E2E-03/04、COMP-01、NEG-01/02；现有工具或预算不足时记录具体阻断，不改题或放宽后条件。
4. 为五项双层故障补实际 native 样本。HTTP worker 收尾与模型槽位空闲分别证明；迟到结果只用于原回执读取。
5. 通过重复、代表性的业务样本建立时延/资源/恢复结果，再决定日常使用资格。真实外屏、横屏、折叠切换仍未资格化。

## 冻结出处

| 输入 | SHA256 |
| --- | --- |
| 完整组合原件 | ab038c5533a7459c8bb4d94cca008ca0f61ade0d90ad6db0e8ece3ab1af99ae8 |
| 规范化组合 | 87609ca2d6b6701071a1f175acd417e1f3036617884dc09666b9154de25e93f8 |
| provider 源封版 | 7c20af425fa88cf6fd90aa7b902bd7c5c0cb0f1d4e808ac26ddbd4445f61c4ab |
| 固定协议 | d68dd5c17d0ec061f52b60656918867453d67217ac2dc8f5eb43be7dd3ffdf43 |
| 原 aggregator | c3b91281a1076ac6fd782fe722eeedae7384817dcbd89060e94b095be48ce083 |

[build_checkpoint.py](build_checkpoint.py) 只读取既有原件并调用冻结 aggregator，无手机任务执行入口。完整复核需要运营者私有原件树。公开投影不含完整请求、nonce、用户草稿及其摘要、密钥及其摘要、raw claim/native 记录或实际 scope/action/process 身份。
