# 准入前阶段诊断：未采用设计

## 原缺口与不变边界

冻结 R10 `stage_component.py`（19,085 B，SHA-256 `74ff4865d2021e42ae5022d606cfe5732d924e8038d00c3a99b89ebcd4c77d72`）在创建新 home 和进入发布 STAGE-FAILURE 的 try 块之前调用 `L.verify_retired(lease)`。因此该阶段超时可以留下没有新 home、LEASE 或 STAGE-FAILURE 的状态。原 actor 只在 shell 返回后记录结果；transport TimeoutError 不提供原远端 producer 的 terminal/cleanup 证明。host 子进程 return0 也不提供此证明。

本设计不改 R10，也不补造 R10 的 stage terminal。它只规定一个未来新受审候选的被动观察通道。它没有被安装或执行，不签发 admission、retirement、closure、case credit 或新的 owner 身份。

## 必须先解决的传输事实

现有 pinned actor/helper 接口通常在完整 shell 返回后才交付 phone stdout。把阶段 JSON 打到该 stdout，并不能保证 socket 超时时已收到的前缀会保全。不能直接宣称“加 print 就有 durable ledger”。需要新受审 transport reader 或独立 host-side 流式接收器，把实际收到的原字节前缀及时持久化，并分别记录 expected/received/stored bytes、EOF、truncation、fsync 结果与解析是否完整。

如果仍使用当前一次性整包 transport，则只能形成 durable host request/actor boundary ledger；内部 phone phase 保持 UNKNOWN。不得从主机时间或静态源码推断实际已经进入某个 phone phase。

## 推荐结构

1. **独立 host ledger。** Ledger 位于新观察任务的私有 host 目录，先于被观察调用创建；不依赖 phone 的待创建 stage home。原请求、actor/source/archive/lease/package 的 bytes/hash、原 admission identity、boot 与实际任务/transport identity 都逐项绑定。观察操作本身有单独标签，不借用或重新消费原 runtime nonce。
2. **有限阶段事件。** 在未来新源的受审调用边界发出 `archive.enter/leave`、`validate.enter/leave`、`modules.enter/leave`、`native_root.enter/leave`、`verify_retired.enter/leave/error`。保留原验证函数、实参、返回值、异常及其先后顺序。事件必须绑定真实发送者 PID/start_ticks/PGID/SID 与 boot；新包装代码使用自己的源 hash。
3. **原验证只运行一次。** Observer 不调用 stage、不创建 stage home、不发 native/tool/model 请求、不授予 reservation、不重放旧请求、不补跑某个“缺失阶段”。原 stage 的一次执行仍由唯一 Root operator 和正式 fresh admission 控制。
4. **传输与持久化分层。** Phone 事件写入已审的有限、非阻塞事件通道；host 按接收顺序保存原字节、sequence、前一记录 hash、收到时的 host monotonic/unix 时钟与 durable publication 状态。两端时钟不能互相冒充。缺失、乱序、半帧、超量与 fsync 失败必须显式标为诊断不完整。
5. **不以诊断改写控制结果。** 不延长原 stage transport 的 90 秒预算，也不改变实际源/lease 原件定义的 lease 期限或 reader/scanner 预算；不跳过任何 guard/lock/absence/readback。stage 对剩余时间的 900000 ms 检查不能被解释成 lease 完整寿命。新 instrumentation 的时间计入同一原预算。诊断路径的失败不允许把原 fail 变为 pass；也不能丢失原异常并仅保留 logger 异常。

## 最小事件字段

每个事件保留 `schema`、`observer_identity`、`observed_attempt_identity`、`source_sha256`、`phase`、`event_kind`、`event_sequence`、原 sender 的 boot/PID/start_ticks/PGID/SID、sender monotonic/unix 时钟、`previous_record_sha256`、原始 payload bytes/hash。主机另附实际接收与 fsync 信息；不能覆盖 sender 字段。

异常事件至少保留原 exception 类型/文案和有界 traceback 标识。源/配置的私密内容不必复制进事件；使用对应原件 descriptor。阶段事件仅说明观察到某一步，不说明后续未发生。

## Terminal 与闭合语义

Ledger 必须区分 operator job、actor、transport 与 phone stage producer 四个层级。只观察到 actor timeout 时，phone producer terminal 仍为 null；只观察到 host wait exit0 时，phone stage 仍可能 unknown。迟到事件不能改写已经形成的原终态，也不能授权重试。

只有同次原 producer 的确切身份、真实 wait/terminal 及输出完整性原件能够支撑对应层 terminal。当前 `/proc` absence、目录 ENOENT、结束后的只读扫描与 host JSON 无法追认原时点零作用。Ledger 的 `complete` 只指 ledger 自身的字节/发布闭合，不能命名为业务 closure、retirement 或 fixed19 PASS。

## 只读诊断的另一个陷阱

不能把完整 `L.verify_retired()` 自动称作纯只读函数：成功路径还包含真实 absent-group/lock 门。单独的诊断若只获准读取，不得通过替换 lock/signal 函数来“跑过”这一段。可选方案是被动观察一次已独立准入的原执行，或显式命名仅做无副作用的 archive/source/pure-verifier 诊断；后者必须在其源/输出中承认没有验证 lock/runtime admission。

## 采用前的验证门

在本地 fixture 中验证 transport 断开、半帧、乱序、超量、磁盘错误、ledger fsync 失败、原 verifier exception 和 host wrapper exit0/phone unknown 分离；验证 observer 不能调用生产 stage 或申请 reservation；对所有路径保持原预算、原异常优先级及零 native/model/input 作用。然后对新 instrumentation、传输依赖、ledger schema 与 reader 单独取得源码 review 和 exact head/base checks。现阶段状态仍为 **DESIGN_ONLY / HOLD**。
