# Sender-r5：Root 单次组件任务执行与原件路径

状态：仅主机端封版；原69项fixtures+5项版本绑定检查PASS。r5仅更新component-r3路径/source/完整policy及helper引用。反向替换后的文本和AST与r4相同。retirement guard5aaf原字节；旧失败、实际resolution7e062、proof2bdd、草稿CAS、150秒总期限、25/15秒ready余量、唯一Send保持不变。

Main项目根B150：
/operator-workspace/razr60/phone-local-v150

固定组合：component source-r3 83e867936e6db85e5187a6e8853c40b7bdd9804a27cdd09591c1a8274a950295；完整rule b83280ba8be66d532e94a66fb5f03c586478deb62f33bc89649d3298cb08cb2f；patched policy3983cdba0e46e826fcf9d1cd67821c998849af7cc45fc863f2ce950897dde613。component MANIFEST为dc5d32f4ab66eee892084e5d1fff5e9887d5fe89f63d5cf935be1429948a798b。原r2/旧策略不能混用。

## 1. 全部准备完，再启动parent lease

Root按已封parent-r2计划完成stage/独立核验，随后才启动600秒parent lease并记录真实executor instance。不要提前消耗lease。手机GNU根：
STATE=/var/lib/trillionnium/owner-open/phone-local-v150/component-probe-r6

确保STATE、contracts、claims等目录canonical/root0700；已有状态只核验不删除。source-r3和contract私有0400/0600；ready/attempt记录0600。使用Main B150/component-probe-r6-r3/prepare_component_probe.py生成全新契约和原文，绑定实际selected session/profile、parent instance及原proof/resolution；Root复制contract至STATE/contracts/NONCE.json。原用户非空草稿继续保存在原private preservation JSON，不打印其原文或SHA。

## 2. Main启动sender一次；Pocket4等prepared标记

    python3 -B "$B150/send_new_native_task_r5.py" LABEL REQUEST PREVIOUS_REPORT \
      --preserved-draft PRESERVATION_JSON \
      --retirement-resolution "$B150/ondevice-contract-review-v150/retirement-resolution-r4-01/pocket4/RESOLUTION.json" \
      --evidence-root component --component-contract NEW_CONTRACT_JSON --execute-once

PREVIOUS_REPORT必须对应当前实际选择；首次post-retirement使用原Visual04真实失败报告。REQUEST/NEW_CONTRACT来自新r3 prepare，PRESERVATION_JSON必须为原非空稿的exact_utf8_b64/utf8_sha256。默认不加--execute-once仅build私有preview。不要把preview、actor、原稿或真实请求上传Git。

Sender完成原prechecks后，Root只读Pocket4：
/operator-workspace/pocket4/codex-hepta-natural-LABEL-root-v150/COMPONENT-PREPARED-NO-SEND.json

须为PREPARED_NO_SEND、send_attempt_count0，owner/nonce/contract/source均匹配且原150秒剩余预算足够。然后Root才启动component provider一次，argv必须精确：

    /data/adb/magisk/busybox chroot /data/trillionnium/owner-open/root \
      /usr/bin/python3 -B \
      /var/lib/trillionnium/owner-open/phone-local-v150/component-probe-r6/source-r3/component_probe_provider.py \
      --contract /var/lib/trillionnium/owner-open/phone-local-v150/component-probe-r6/contracts/NONCE.json \
      --contract-sha256 EXACT_CONTRACT_SHA

Sender只读STATE/ready-NONCE.json，核验完整契约/源码/实例、PID/start/cmdline、未claim/未结束、真实phone CLOCK_MONOTONIC余量。首次25秒、最终15秒，保守扣整次P4读取及之后耗时。随后复核草稿、selected scope和全局动作gate，至多Send一次。生产模式不提供--component-contract且不等待ready。无服务启动hook/TCP探针/自动续期。

## 3. 只读原任务终态与私有原件

| 层 | 原件位置 |
|---|---|
| P4入口/观察/草稿恢复 | /operator-workspace/pocket4/codex-hepta-natural-LABEL-root-v150/：SEND.MONOTONIC-INTENT.json、SEND.MONOTONIC-WINDOW.json、SEND-NATIVE-LATENCY.json、COMPONENT-READY-*.original-read.json、COMPONENT-FINAL-PRE-SEND-READY.original-read.json、DRAFT-RESTORE-RESULT.json或延期记录 |
| Main发送wrapper | B150/LABEL.local-once.json、LABEL.actor.py、LABEL.send-result.json；全部private |
| component one-use/服务 | STATE/contracts/NONCE.json、claims/NONCE.json、ready-NONCE.json、service-attempt-NONCE.json、service-ended-NONCE.json |
| component运行原件 | 从claims/NONCE.json读取实际run_dir；STATE/evidence/RUN内provider-in.jsonl、provider-out.jsonl、accepted.json、dispatch-intent.json、native-tool-result.json、original-executor-inspection.json、component-outcome.json或component-failure.json、provider-terminal-intent.json |
| 原native journal | Android /data/trillionnium/owner-open/state/turn-events.jsonl.segments/*.jsonl；GNU /var/lib/trillionnium/owner-open/turn-events.jsonl.segments/*.jsonl；按实际完整5scope抽取，保留原行 |
| 原r6 executor/action | Android /data/trillionnium/owner-open/state/phone-local-v150/executor-r6-component-01/actions/ACTION/；GNU同树在/var/lib/trillionnium/owner-open/phone-local-v150/executor-r6-component-01/actions/ACTION/；intent.json、receipt.json、stdout.bin、stderr.bin |
| 独立component client | STATE/client-receipts/ACTION.*；从真实accepted/claim取ACTION，不新造 |

既有原native哈希核验器：Main B150/acceptance-r4/collector-r4/native_journal_audit.py，6701B，SHA da47d875addc32c0f7f30d178de95d8ebd956a6cb10b59813705feeb7811f0cf；入口verify_records(records,exact_scope)，只核提供记录，不能声称完整全局WAL链。

同目录collect_turn_evidence.py是daily model/业务collector，要求模型round和daily dispatch布局，不直接适配零模型component。组件须独立核native/provider/raw streams/r6 receipt，不能删除其模型条件来冒充PASS。Root另行保留component原件，窄组件验证器单独封版。

## 4. 收口与界限

ready只是瞬时观察，不能预留连接。若窗口错过/被消费/未知读回，保持零Send或原未知终态，不重启服务、不重放原请求。Sender只在原终态和scope/gate确认后CAS恢复原稿；未知时保留private原稿并延期，公共stdout不含原稿或其SHA。Operator恢复不计作模型HEPTA返回或业务成功。

Root按独立parent/component计划退役并核原组退出。组件资格须实际native accepted/started/result/turn.end、原stdout与严格r6原receipt一致。此轮没有模型请求、没有App业务验收；不能折算固定19项、日常资格或折叠屏通过。后续生产health必须另发全新一用请求。
