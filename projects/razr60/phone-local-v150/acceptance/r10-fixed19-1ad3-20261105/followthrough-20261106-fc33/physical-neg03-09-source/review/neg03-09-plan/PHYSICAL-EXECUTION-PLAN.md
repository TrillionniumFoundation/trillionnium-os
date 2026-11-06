# NEG-03—NEG-09：Root 唯一执行方案

状态：源码候选，实际执行输入未绑定。精确候选是 shared 7969、runtime 990；若 R5 父目录问题导致源码改变，需要新的完整 pin 传播。本文件不是手机执行授权载体，也没有可执行的实际任务参数。

## 所有物理项的共同入口

1. 由 Root 先取得最终实际 freezer 两份相同结果、完整 source readback 和 controller 成功原件，再完成正式 source-chain、sealed BUILD、四角色 READY。所有实际角色、模块、owner、lease、15 生产源、配置和 service 必须指向同一个 tuple。
2. 为每项使用新注册 owner/request、完整保留 draft、新 nonce/label、新 scope 和已经关闭的前次 selected task。保留原有 retired/current inventory 校验；未解释的变化不能通过重新基线后当成授权。
3. 通过已审 source constructor 派生 operator 包；独立核对所有 files 和来源反演。实际 source-chain 接口必须用公共入口，不能补一份模拟 BUILD/READY 来绕过。
4. 由原 preparer/admission 读取实际原件并生成 plan。只有 Root 消费它生成的确切命令一次；等待、读取、解释可以重复，effect/Send/signal/Cancel 不重试。
5. 保存 request/start/status/read 原载体、同一 job 的完整 stdout/stderr 双 EOF、exit 状态、原任务 scope、原 action/native/WAL/global ledger、15 源、公开 UI receipt、归档完整字节及 full9 元数据。独立 closer 必须通过，actor 自报完成不构成整项通过。

## 每项最小流程与缺口

| 用例 | 真实源入口 | 原有阶段与必需关闭条件 | 当前仍缺的证据 |
| --- | --- | --- | --- |
| NEG-03 | `physical-component/source/run_physical_component_once.py --execute-physical-case-once` | 同源六轴 synthetic fixture；实际 live-before/portrait baseline；一次旋转；原 mapper/parser 与生产 guard 拒绝；一次恢复观察到的两项 rotation 设置；live-after/PNG/page/bookend 全闭合。 | 当前最终 BUILD/READY 下的实际 baseline、旋转拒绝、零 input、准确恢复和独立 closure。 |
| NEG-04 | 原 `prepare_physical_fault.py --prepare-host-only` 产生 `run_physical_fault_once.py --execute-once` | 原 watch armed 后一次 Send；admission 成功且原 calls/results 均为零；锁定唯一 test-owned carrier 的 pidfd 后一次 SIGTERM；完整终态/unknown、cleanup、原 identity 已消费和无 replay。 | 当前 tuple 的新 host 层和新 physical_native_task 原件。 |
| NEG-05 | 同一 physical-fault preparer/runner | 原首次 disposable probe effect 已出现而结果尚未交 provider；独立公开页面读取且近于当下；pidfd 下重验 eligibility 后一次 carrier SIGTERM；effect 至多一次、unknown 不提升 success。 | 当前 tuple 的实际首效、断连时点、原生 ledger/公开 receipt 和无重复效果。 |
| NEG-06 | `host-neg06/source/execute_namespace_once.py` | 一次原隔离 namespace；当前 daily 经真实 HTTP worker 向 deterministic hold fixture 发一次请求；短测试 deadline；model_timeout、零 dispatch、原 worker wait/pgid 消失、claim 保留、无 fallback/relaunch。 | 当前 tuple 的实际隔离主机运行与原件。fixture 不证明 bound real model server 的 slot/queue 清理。 |
| NEG-07 | 同一 physical-fault preparer/runner | watch 对准确 r6 worker 身份、uid/domain/exe/parent/pipes/action/generation 核验后一次 pidfd SIGSTOP；原结果 deadline；durable pre-late 四文件 fence；只观察 late 原结果；terminal/providerin/providerout/claim 均不得改写。 | 当前 tuple 的原 worker 暂停、真实 deadline、持久化先后关系、迟到原件和 effect≤1。 |
| NEG-08 | `ui/source/cancel_native_once_r10.py --execute-once`，后接完整 phone/P4 capture 与 CPU/native closer | 原模型进程活跃且原 dispatch=0；公开 HEPTA selected task CAS 与唯一 Cancel 节点；一次 UI Cancel；turn.cancelled 或明确 unknown；零 phone effect；原 HTTP pgid 清理、claim 不释放。 | 当前 tuple 实际阶段命中、唯一 Cancel、清理/claim 与完整独立 closure。 |
| NEG-09 | 同上 | 原首次 effect 独立确认；必要时只由显式 operator 导航到 HEPTA Cancel UI；一次 Cancel；保留已发生效果；provider 不再输入/强制 return；取消不是业务成功。 | 当前 tuple 首效后实际 Cancel、完整公开 receipt/ledger、后续零 input/native return、原进程清理和 closure。 |

### NEG-03 的显示范围和恢复

原固定协议允许原形状 read-only fixture 或一次明确安排的 physical negative，且要求分开标注结果。本包六轴覆盖 screenshot/return 的 display、rotation、geometry：每次真实 parser 拒绝后，后续 `phone.tap` map 也拒绝。它们是 synthetic native frame，没有向另一个显示器注入输入。

真实物理路径是一次 rotation，不能把它写成已操作外屏。runner 先记录本次 `accelerometer_rotation` 与 `user_rotation`，在 effect 前持久化 inverse；只恢复这两项已观测设置。若原 phone task 终态未知，不自动执行 inverse。单独 `restore_existing_rotation_once.py --inspect-original-then-restore-once` 仅在原 wrapper 已 join/rc0/双 EOF 且准确阶段被原件证实后供 Root 审定使用。

### NEG-04/05/07 的唯一故障动作

保留原 `signal_fault_once_r10.py` 全体，没有新 SSH 目的地或凭证。原 host route 固定经 `ai395-usb4` 到 `pocket4-usb4-fast`，保留 BatchMode、StrictHostKeyChecking 与 ConnectTimeout。只有已经确认属于本次测试的 carrier/worker 才可被 pidfd 选中；不能命中 service/native parent，没有普通 PID 回退。

NEG04/05 是一次 carrier SIGTERM。NEG07 是一次准确 worker SIGSTOP；该 actor 不添加 SIGCONT，也不能把 timeout 后的未知任务重发一次。watch 原有总预算与 actor deadline 不扩展；外层的归档等待不是 native action deadline 的延长。

NEG07 的四文件 fence 需从同一仍在运行的原 receipt 取得完整 terminal/providerin/providerout/claim，完整写入与文件/目录 fsync 后再次读取 receipt 的 full9 身份。`PRE + DURABILITY < LATE < POST` 必须由完整原件证明。迟到结果只能作为证据；任何终态字节变化或第二次 effect 都不能通过。

runner 自动进行一次 sender、once actor、read-only captures 和原 independent verifier，不能在 controller 超时后重新运行整个 runner。先读取同一 job 的原始状态与归档；unknown 保持 unknown。

### NEG-08/09 的 UI 取消与收尾

原 cancel actor 在 P4 导入已经 pin 住的 preserved-UI 工具，**只复用它的 `route()` / `shell()` 方法**。这不是运行 preserved-UI 工具自己的 `main` 或 apply-packages 操作。实际手机命令仍通过已审 route，不能从任务以外的会话取消进程。

actor 会核对自身 UI 包的全部八个 source member、`production-pins.json` 与 manifest 中同一 15 源字典，验证 selected task CAS、公开页面和 native scope。observer 的 v3 修复只增加已验证 wire/scope 参数，保留整个阶段 gate。

phase window 错过就保持零 Cancel；不能再用旧 label/scope重试。NEG09 访问 Cancel UI 的 operator 导航必须单独标记，不是模型成功返回 HEPTA，也不能算 COMP01。Cancel 后只读原件；不再发 provider follow-up 或强制 return。

actor 的 `physical_case_pass=false` 是有意保留的。它只能给出动作原件，最后必须经 phone/P4 两侧完整 capture、原 CPU model-worker/slot 清理证明、原 native ledger 和独立 `root_cpu_negative` / `close_cpu_negative` 关闭。

## 同一组合的主机层与模型超时

`host-five` 候选保留原 disposable counter、once-only 认领、duplicate rejection 和 terminal fence，只更新当前真实源码/config/service pins。Android typed command 在主机 counter 路径里只作为保留数据，不能说成执行过手机效果。

NEG06 原协议明确使用本地 deterministic HTTP hold fixture、短测试 deadline，而不是 live service deadline。新候选仅更新源输入与选择 NEG06；保留原 unshare/bwrap 隔离，失败没有 namespace-free fallback，不挂载真实密钥或模型权重。实际进程组结束和 fixture idle 可实测；这些结果不能扩大为真实 llama server 的 slot drain/abort 资格。

当前这两个主机家族也尚未运行。旧 host 成功完整保留，与本次实际 7/70/15 的 source controls 分开。

## 必须保持不可自动修复的状态

* source/package/role/lease/READY 不匹配：在 effect 前拒绝，不放松数量、扩大字典或跳 gate。
* 原阶段尚未被独立原件证实：不推断 eligible，不发送 fault/Cancel。
* 断连或迟到造成 unknown：不推断业务成功，不重派发，不释放原语义身份。
* 原 controller 回执不足：只读对账同一 job，不调用同一 execute 入口第二次。
* effect 已发生：保留该效果和原 claim，不通过额外输入或强制 return 尝试“补全”失败。
* 未取得原 closure 的资源基线/恢复证据：保持该项未关闭，不能用 fixture、旧 tuple 或当前 source hash 替代。
