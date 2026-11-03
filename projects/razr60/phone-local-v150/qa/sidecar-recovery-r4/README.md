# v150 r4 实机 sidecar 定向恢复套件

状态：已准备供 root 主流程审阅、部署和执行。此目录的准备工作没有连接手机、运行 ADB、执行 UI 操作、提交模型请求或运行 native r5 任务。无参运行只输出 review-only 设计摘要，不打开 socket，不创建 QA 目录。

## 范围

这是一套 **真实手机上的 sidecar 组件测试**，使用已安装、固定 SHA256 的 r4 tool_client.py 和 Android sidecar。它不经过 native r5 task/tool ledger，也不包含 VLM 推理或视觉/Unicode 业务验收。通过五例不代表固定 19 项协议完成，也不代表日常使用资格、外屏/旋转/折叠切换资格。

固定输入：

- client：b298ac86fdf57dd0c7dc5159febf114ed176398d32ea672c9abda4a6eb621539
- 实际运行中的 sidecar executable：796f223a98553afc83eb875b3a89aa03f07d0d069a3fb5ab953f849a7f8e84c0
- abstract UDS：hepta_phone_local_v150
- Android state：/data/trillionnium/owner-open/state/phone-local-v150
- GNU chroot state：/var/lib/trillionnium/owner-open/phone-local-v150

脚本先验证 root 私有目录、原 client 字节、UDS peer UID、/proc/<peerPID>/stat 身份及 /proc/<peerPID>/exe 原字节；再确认 sidecar health 为 ready，且整个测试期间 server_instance 不变。若现有 GNU chroot 中 /proc/原进程不可读，必须记录 precheck 失败并停止。本测试不授权为它新增挂载、改变 SELinux、逃离 chroot 或替换服务。

## 五例与正确终态

每次显式运行产生一个新 24-hex nonce 和恰好五个新 32-hex action ID。出现 ID 碰撞或已有 action 时直接失败，不换 ID 重发。

| 例 | 注入方式 | 关闭条件 |
|---|---|---|
| 发送完成前断连 | 发送完整 4-byteBE 长度头，以及少最后一个字节的 execute JSON，然后关闭 socket | 原 ID 持续 not_found；无 action 目录/intent；marker 0。因为未建立 action，不捏造 terminal/join 回执 |
| effect_started 后断连 | 只发送一次完整 execute；读取原 receipt 和 synthetic marker，证实 running+effect_started 后关闭原 socket | cancelled / client_disconnected；原动作实际启动一次、marker 1；真实 wait/join 和 PGID absent |
| client 开始工具后取消 | 启动原 installed client CLI；等原动作已启动和 marker 1，再仅给该 Popen client 发 SIGTERM | client 被 SIGTERM 终止并 wait；原 sidecar action cancelled / client_disconnected，进程组已清理 |
| executor 超时与潜在迟到结果 | marker 后 sleep 2 秒再安排 late marker/output；工具 deadline 650ms | 原 client 72；sidecar timed_out / timeout；marker 1；等待越过原迟到写入时间后仍无 late marker/output |
| 重复只检查 | 新 action 首次真实完成；同一个 client 以原 ID 再调用，必须走其 O_EXCL claim 的 inspect-only 分支 | 第一次 client 0；第二次 76，stdout 不复述旧输出；原 intent/receipt/stdout/stderr 四文件 SHA 完全不变，marker 仍 1 |

其中四个真正启动的 action，全部必须满足：

- original action_id、command_sha256、server_instance、timeout_ms 与本次计划一致；
- terminal=true、effect_started=true、process_group_established=true；
- waitpid_joined=true、process_group_absent=true；
- intent_parent_sync_complete=true、dispatch_count=1、can_redispatch=false；
- stdout/stderr 原始字节数与 SHA 对得上；
- synthetic primary marker 恰好一次，late marker 不存在。

原动作的终态、原文件 SHA 在迟到窗口之后再次读取。任何不确定、不同终态或未完成清理都保留为失败/不完整，不提交替代 execute。出错只关闭本套件拥有的 socket、结束本套件创建的 client，然后只 inspect 已存在的本次原 action。

## 有界与写入范围

每个 shell tool timeout ≤3000ms，其中超时例为 650ms。所有 synthetic shell 仅使用 set -eu、umask、printf 和 /system/bin/sleep；所有 marker 写入都限定在 Android HOSTSTATE/qa-<nonce>。没有 su、am、input、uiautomator、ADB、mount、后台 shell、setsid、模型命令或业务文本。

脚本自身有 70 秒执行预算。清理只等待自己创建的 client，原回执的异常后只读收口总额外 3 秒。主流程应同时使用 85 秒 TERM + 3 秒 KILL 的外层 watchdog，使整次执行在 88 秒结束。内层预算是测试程序边界，**不是产品预算耗尽验收**；实际 native/model 的预算耗尽、取消和断连链仍需独立验证。

执行前由 root 主流程确认没有活动业务工具占用 sidecar。busy/recovery_required 会使套件停止，脚本不会清除或绕过恢复门禁。

## root 执行方式

只由 root 主流程把脚本作为独立 QA 文件放入共享 state，例如：

/data/trillionnium/owner-open/state/phone-local-v150/qa-programs/phone_sidecar_recovery_suite.py

其 GNU chroot 内路径是：

/var/lib/trillionnium/owner-open/phone-local-v150/qa-programs/phone_sidecar_recovery_suite.py

此处不更改已封存 binary、client、provider、Magisk 模块或模型配置。复制后先对照 FINAL-MANIFEST.json 中的脚本 SHA256 读回。

在现有 GNU chroot 内，仅当已有 GNU timeout 可用时，执行：

    /usr/bin/timeout --signal=TERM --kill-after=3s 85s \
      /usr/bin/python3 -B \
      /var/lib/trillionnium/owner-open/phone-local-v150/qa-programs/phone_sidecar_recovery_suite.py \
      --execute-new-suite

若 GNU timeout 不在该路径，由 root 使用现有外层操作环境设置相同的 85+3 秒上界，不为本测试安装工具或变更挂载。

不带 --execute-new-suite 只做 review-only：

    /usr/bin/python3 -B /path/to/phone_sidecar_recovery_suite.py

本准备目录中的 PREPARATION-VALIDATION.json 对应初稿；FINAL-PREPARATION-VALIDATION.json 和 FINAL-MANIFEST.json 对应交付版。任何准备校验都不是 phone PASS。

## 原始证据

启动时 stdout 先公布新 nonce 和实际 QA 路径。运行产生的证据都在该 qa-<nonce> 目录，并保留 sidecar 自身原 action journal：

- 写一次的计划，包含五个新 ID、完整 synthetic command 与 command SHA；
- 每次原 inspect 的完整 JSON，health、signal、client 启动/退出记录；
- 原 client stdout/stderr、claim/result/last-inspect 文件；
- sidecar intent.json、receipt.json、stdout.bin、stderr.bin 原始字节副本；
- 迟到观察与原 journal SHA 一致性记录；
- EVIDENCE-MANIFEST.json：所有既有证据文件的 SHA/大小；
- SUMMARY.json 与 SUMMARY.sha256：只创建、不覆盖的最终结果及 manifest SHA。

summary 的 PASS 仅代表这五个 sidecar 组件案例通过。它明确标注 native_r5_task_or_tool_ledger_used=false、model_inference_used=false、nineteen_item_business_protocol_completed=false。任何实机执行失败时都不得重用同一 ID 重新 execute；先读本次原 receipt。原用户请求、旧业务文本和已有动作不在本套件中。
