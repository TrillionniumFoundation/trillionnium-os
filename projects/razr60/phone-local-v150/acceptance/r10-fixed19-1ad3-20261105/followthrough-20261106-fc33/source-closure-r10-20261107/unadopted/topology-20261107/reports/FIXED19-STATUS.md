# 当前 fixed19：19 项均为 HOLD

本表把冻结协议与当前 R10 失败身份对齐；不修改原协议，也不把旧 selected component 或历史 PASS 记为当前组合资格。

协议：`stock16-phone-local-fixed-set-r4`；原件 `originals/ORIGINAL-PROTOCOL.json`，SHA-256 `c573959e59fd9fbe7a850d6d2d6d747e3135718493f15de4a8acde850bad93b0`。

历史库存表 SHA-256 `4699ad5f62ae6ec7b74f19422d455c56c258b1a06be75fc273a38f063eebd804`。旧库存扫描 37 个 attempt；其 12 个历史协议 PASS、2 个 FAIL 和其余未写协议结果的原件保持原义。旧 NEG-01 的 component closure 属于 a1055-final04；它不是当前 fc33-r10 的 closure。

当前 R10：`root-r10-neg01-fc33-r10-bound01`，nonce `4e5480a8952443bd18fa603b81f8efe9`，原 root job `1a1b7ef6a3a-12894-cbf`。phone actor 在 stage 处 90.299 秒 TimeoutError，原 nonce 已消耗，host export 明示尚未 retirement/qualification。离线优化 PASS 不改变这一状态。

| Case | 协议确切名称 | 必需层 | 当前状态 | 通过门槛 |
|---|---|---|---|---|
| E2E-01 | 一次新截图完成一个全新随机视觉挑战并返回HEPTA | model_e2e | HOLD | 新截图 JPEG 与 native receipt/实际模型请求同 hash；只选择一次；同屏挑战码与 HEPTA_VISUAL_OK 回执相符；真实返回 HEPTA；原 native complete + entire_request business_verified=true。 |
| E2E-02 | 全新中文/emoji/换行输入、确认、公开回执与返回 | model_e2e | HOLD | 全新中文、emoji、真实换行及特殊字符输入逐 UTF-8 字节一致；提交一次；编辑器、公开读回及四行公开回执均吻合；真实返回；缺任一条件须 turn.fail。 |
| E2E-03 | 计算器完成全新随机简单表达式并核验结果 | model_e2e | HOLD | 新随机 (a*b)+c；独立预算期望值；已安装计算器唯一公开结果 view 的实测字符串吻合；按请求真实返回；未知作用不能重复计算。 |
| E2E-04 | 只读查看设置中的公开系统版本字段 | model_e2e | HOLD | 当前 Settings 包、唯一公开字段、焦点与独立只读系统观察吻合；零设置变更；任务未要求返回时不能强制返回。 |
| COMP-01 | 显式返回：launch状态和实际焦点双核验 | component_direct | HOLD | 一次 return_hepta；立即保存 launch rc=0、恰一个 Status: ok 与精确 activity；inner display focus/app/top-resumed 一致且 keyguard=false；仅授予 component 层。 |
| NEG-01 | 截图后焦点切换：必须在input之前拒绝 | component_direct | HOLD | 新截图后安全切换焦点；待执行 tap 仅一次；guard=70 或明确已知更早前置拒绝；独立前后公开计数证明两页零 input；image 消耗、不重试；本次 closure/late boundary 齐全。 |
| NEG-02 | 同viewport内容变化：精确像素guard必须拒绝 | component_direct | HOLD | NEG-01 完整结算后新身份；viewport/focus 保持不变、PNG SHA 改变；guard=71 且在 input 前；公开状态/计数无作用、不重试；本次 closure/late boundary 齐全。 |
| NEG-03 | 外屏或旋转：拒绝未资格显示配置 | component_direct | HOLD | 拒绝 display 0 portrait 资格外的截图/tap/公开返回；不得向其他显示注入 input；fixture 与实机结果分开。 |
| NEG-04 | 断连发生于dispatch之前 | host_isolated, physical_native_task | HOLD | 准入后、dispatch 前断开自有测试传输；零 tool dispatch；原 claim 消耗；无自动新流/请求重放；未见原终态时保留 UNKNOWN；另补实际安装组合 physical_native_task。 |
| NEG-05 | 作用已开始后断连：保持未知且不重放 | host_isolated, physical_native_task | HOLD | 作用开始后结果到达前断连；独立计数至多一次；未知不推成功、不重试；重连不能重用原身份；另补实机层。 |
| NEG-06 | 模型超时：有界结束且清理原进程组 | host_isolated | HOLD | 隔离 HTTP model fixture 超时；原 fail frame 含 model_timeout；business=false、零 dispatch；原进程组/slot 有界收尾；无模型/账号 fallback、重启或 claim 释放。 |
| NEG-07 | 执行器结果超时：不能用迟到结果认定成功或再执行 | host_isolated, physical_native_task | HOLD | 执行器结果超时；保留原 dispatch；迟到结果仅作证据，不改写原终态/UNKNOWN、不再执行；business=false、cleanup 明确；另补实机层。 |
| NEG-08 | dispatch前取消 | host_isolated, physical_native_task | HOLD | 准入后首次 dispatch 前取消；保留 turn.cancelled 或丢失确认对应 UNKNOWN；零 phone 作用、无自动导航；business=false；原 HTTP-client 进程组确认收尾；另补实机层。 |
| NEG-09 | 首次作用后取消 | host_isolated, physical_native_task | HOLD | 一次确认作用后取消；只保留已观察的一次作用，无后续 input/强制返回；不得宣称业务完成；不重放、不释放身份；另补实机层。 |
| NEG-10 | 图片字节预算/过期图像/旧round绑定 | host_isolated | HOLD | 独立新 fixture 分别拒绝图像预算不足、>120s 旧图、错误 call_id 和旧 round；在 dispatch 前拒绝；单图≤196608B、整 turn 图像≤393216B，不提额。 |
| NEG-11 | native输出损坏/截断/错误身份 | host_isolated | HOLD | 分别损坏 call_id、sequence、byte count、exit、truncation、Base64、source/hash；每项均拒收 image/text/return 事实，不能合成业务成功；fixture 明示 synthetic。 |
| NEG-12 | 部分任务被模型说成完成：必须失败终态 | host_isolated | HOLD | 只有 input helper receipt、缺公开回执/return/entire_request coverage 时，wire=turn.fail/business_not_verified，业务 sidecar 列缺项；native complete/model completed 不得覆盖缺项。 |
| NEG-13 | 一次性模板并发/旧nonce重用 | host_isolated | HOLD | 两个不同 semantic turns 竞争一个新 nonce/request：恰一次 O_EXCL 绑定；错误 scope 不消耗模板；已消耗模板不能再准入/dispatch；保留所有 claims/bindings。 |
| NEG-14 | 容量/原子rename竞态与资源收尾 | host_isolated | HOLD | 仅识别的 enumerate→rename→lstat 临时名竞态可容忍；未知文件/I/O/canonical evidence 丢失须 fail closed；不为容量删 claim；已确认 worker/child/fd 收尾回到实测基线。 |

## 所有案例共用的证据门槛

同一实际组合须绑定源码/包/helper/APK/native/model/config 身份、boot/session/policy、精确请求及一次性 nonce。每个 E2E 使用新 128-bit 随机 nonce；组件或 fixture 使用新隔离身份。由一个 Root operator 串行执行手机案例，旧请求、旧流和旧 nonce 均不重放。

保留真实模型 HTTP 请求/响应与 slot receipts、native frames、完整 stdout/stderr 和原 terminal、业务 sidecar、公开 UI/作用计数、资源基线与恢复原件。模型文字、host exit0、单一 component PASS、fixture PASS 均不足以关闭整个案例。NEG-01 必须先有本次完整 closure 与 late boundary 才能准备 NEG-02。

冻结业务预算：最多 7 次连续 tool calls、8 个 model rounds、turn 300 秒、默认单轮 model deadline 120 秒；须先读回实际 live 配置，不能静默提额。这里的业务预算与原 stage transport 的 90 秒预算是不同层，离线测试均未改动。stage 对剩余 lease 时间的 900000 ms 上界不等于 lease 的完整寿命；lease 期限仍须按实际创建/加载合同与原件判断。每项须计量 latency、usage、cost、resources、evidence、restoration。

## 五项实机故障层

NEG-04、NEG-05、NEG-07、NEG-08、NEG-09 都需要 host_isolated 与 physical_native_task 两层。当前五项均 HOLD；旧 host fixture PASS 不代替实际安装组合的实机原任务。实机需用新、有界、可丢弃任务，明确真实模型与 fixture provider，保留原终态/UNKNOWN、最多一次作用计数、原进程组收尾和迟到结果边界。

## 正式 BUILD、安装、健康与回滚

均 HOLD。需要受保护集成目标及 exact head/base checks/review 与采用候选一致；可重建 source/tree/toolchain/dependencies/artifact 材料；同一安装组合的安装前后完整字节读回与模型/配置身份；四角色 READY；独立新 nonce health 的真实终态；完整业务证据。回滚必须单独准入并验证实际回滚后的读回/健康，不能把当前旧对象的存在当作回滚已通过。具体 release 合同必须按其原件采用，本表不另造 BUILD 成功或 rollback 授权。

## 日常与独立运行资格及显示支持范围

均 HOLD。冻结协议明确一次 fixed19 suite 不能推出 daily-use reliability。当前报告没有预定样本数、运行窗口已完成的原件，因此不能给成功率、延迟分位数或资源/副作用达标结论。后续必须在运行前固定样本与窗口，并包含重启、睡眠、断线、取消恢复、正确返回、独立运行及完整成功/失败/UNKNOWN 分母。

协议已有的显示资格仅 display 0、1224×2992、rotation 0，external_display_qualification=false；本报告没有把此历史配置当作当前实机读回。NEG-03 要拒绝资格外显示/旋转。外屏、旋转、折叠若扩大支持，须各自冻结范围、恢复方案与独立实测材料，不能从内屏 portrait 结果外推。

## 保留与未知

原 UNKNOWN、不确定作用、R7/R8/R9/R10 失败、first-launch gap、消耗状态和历史 closure 都保留。当前 absence 仅证明所声明时点/范围的当前观察；不能改写原时点终态或全局零作用。DSU、布局恢复材料及 UNKNOWN 原件不得由本候选清理。
