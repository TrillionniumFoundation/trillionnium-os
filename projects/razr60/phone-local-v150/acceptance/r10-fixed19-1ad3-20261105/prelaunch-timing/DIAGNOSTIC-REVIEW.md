# NEG01 启动前租约拒绝诊断

结论：本次在执行 `remaining(510)` 时拒绝，发生在准备标记校验之后、组件启动调用之前。固定 600 秒租约要求启动前严格剩余超过 510 秒，所以准备窗口必须严格小于 90 秒。准备标记的输出落盘时间对应已用 **90.293360750 秒**、剩余 **509.706639250 秒**；这个时间点已经越过门限约 **0.293361 秒**。实际失败调用更晚，没有单独记录该调用的时间。

本报告只核验现有 25 份 Mac 原件和精确固定源码。没有启动进程、调用手机/P4、发送信号、新建 nonce、重试或修改任何时间门。原失败仍保留。发送端在 Root 失败时的状态是未 join、未 EOF 的未知；发送端后续自然退出及草稿恢复由 Root 另行封存，不能由本报告的空输出或 prepared 标记代替。

## 同一 Root 进程中的阶段耗时

起点按 `OUTPUT-CAPTURE.execution_deadline_monotonic - INTENT.maximum_wait_seconds` 计算；终点是实际 child join。各阶段均属同一 coordinator 时钟。异步 sender-execute 与 sender-prepared 重叠，没有重复计入总时长。

| 阶段 | 实际 child 耗时（秒） | 该 child 的原始上限（秒） |
| --- | ---: | ---: |
| prepare-material | 0.211021125 | 30 |
| host-stage-material | 0.463000959 | 90 |
| phone-push-material | 0.970996167 | 145 |
| phone-copy-material | 0.979644583 | 95 |
| phone-push-stage-source | 1.046486500 | 145 |
| phone-copy-stage-source | 0.950219125 | 95 |
| phone-stage | 57.613468000 | 145 |
| sender-preview | 0.157154708 | 20 |
| sender-prepared | 27.806571125 | 120 |

首个 child 启动至 prepared child join 共 **90.291085416 秒**；九个顺序 child 耗时之和为 **90.198562292 秒**，阶段间及本地处理差额仅 **0.092523124 秒**。两个主要阶段是 phone-stage **57.613468 秒**、sender-prepared **27.806571125 秒**，合计 **85.420039125 秒**，约占总窗口的 **94.60%**。

## 内层原件补充

phone-stage 的原始 phone_once 回执记录 **57.097871981 秒**，外层 Host capture 与它之差约 **0.515596019 秒**。这表明主要耗时发生在 P4 包装器范围内；该计时包含 route、手机 baseline、一次手机命令和包装器持久化，不能把全部 57.10 秒都归给某个 stage 函数。

真实 stage 输出为 `PRIVATE_COMPONENT_INPUTS_STAGED_NO_ROLES`，service_launches/native_tasks 都是 0。该调用完成了五个历史组件边界校验，并核验当前完整盘点的 **2,413 个条目、16,401,835 字节文件内容**。九个新建目录的同一手机文件时间点跨度为 **88 毫秒**；这只是这些创建事件的跨度，不是 stage 全体写盘、后置校验或命令的计时。

发送端 marker 记录原 150 秒 pre-Send 预算剩 **123.192114824 秒**，因此在它自己的时钟内，进入该预算至生成 marker 已用 **26.807885176 秒**。这与外层等待 marker 的 27.806571125 秒相符；二者差额约 **0.998685949 秒**，包含 actor 预算之前的准备和读取/传输开销，不能分配给某一调用。源码在 marker 前完成草稿 CAS、UI 读回、真实原任务 Inspect 与原件核验、retirement/selected identity 复核；这些是真实准入步骤，不是无意义的固定等待。

## 510、420、300 与 60 的关系

- 600 秒原租约从任何 prepare 之前开始；启动前 `>510` 强制准备 `<90`。
- listener 在实际 listen 时另验原租约剩 `>420`，随后 service 窗口为 420 秒、accept 窗口为 120 秒。
- 接受连接后，原生连接截止时间是 `min(now+300, service_deadline)`；Root 的 setup witness 在这个连接中执行，消耗这 300/420 秒预算。
- `510−420=90` 是门限处留给启动至 listener 准入工作的余量。`510−60−420=30` 只是条件算术，不能称为保证剩余 30 秒。detached launcher 与 supervisor 都会再次执行 verify_retired，之后还有 inventory、sidecar/provider 准入。
- 60 秒 phone request、80 秒 P4 child wait、115 秒 Root 观察等待都不会延长原租约；观察超时也不是远端无效果证明。

因此，仅省下本次约 0.3 秒以跨过 510 门，并不能证明后续 listener 仍有足够时间。没有依据把本次失败归为必然可重试的瞬态。

## 可独立审查的耗时压缩方向

最明确的源码重复点位于 `late_boundary.py`：同一 chain row 先经过 boundary_from_original，再由 closed_boundary_originals 再次调用该函数；历史分支多次 raw-load/compile 相同的 R7 common/reader；boundary、closure、ancestor-tail 校验又多次重新编译并纯校验同一 non-native verifier 和三个固定历史原件。

可候选化的是**一次 verify_current 调用域内、以完整精确输入为键的纯校验结果复用**。它必须绑定原始源码、原件字节、descriptor、代际输入及固定记录值，返回不可变结果或防修改副本，并在调用结束时丢弃。当前文件 full metadata/路径/inode 检查、末尾 recheck、完整 live inventory、group/endpoint 缺席、锁、外部构件及实时 policy 全都继续实际执行。

这只是可审查方案，没有修改源、没有声称已证明某个节省量。下一阶段应先用固定原件的 host-only 数据集确认重复调用数量与纯计算耗时，再验证输出等价及坏输入拒绝敏感性。不得使用跨调用的未经重验缓存、旧 live 状态结果、降低时间门，或未经并发证明就让 sender UI 操作与 stage 盘点重叠。

## 原件与复核

`READBACK-MANIFEST.json` 保存首次 23 件的 Mac 路径、独立版本与 SHA；`READBACK-BATCH-2.json` 保存两个新增 stdout 原件；`originals/` 为全部精确字节。`decoded/` 只保存已验证外层包裹中的 stage stdout 和 base64 marker 原始字节，未重序列化。`DIAGNOSTIC-REVIEW.json` 汇总所有原件 descriptor、固定源码 pins、精确算术和证据范围。
