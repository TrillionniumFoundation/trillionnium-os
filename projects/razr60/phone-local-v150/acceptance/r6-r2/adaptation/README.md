# r6-r2 验收支持：已封源码，尚未执行新任务

本包只适配新的 provider-r6-r2 源码组合。固定 19 项的 case 对象、通过条件、7 工具 / 8 轮 / 300 秒限制和显示范围保持原值。健康、组件、恢复与 host 测试分别统计，不计为日常业务成功。

当前 source seal 为 a8bd87b3d50c993b3e4ac7799ca66dd8e84cbd7925deb7e641e5cc66c1bdb7c1。实际模块组合由 Root 提供完整冻结文件，不能仅以 source hash 合并不同组合。原 r6-r1 启动前自检失败、原 r5-r3 健康失败以及其后恢复记录全部保留。

## 当前路径

- 物化器：acceptance-r6-r2/materialize_case_r6.py，原 6ec2 源码字节未变。
- 协议与聚合：acceptance-r6-r2/fixed-acceptance-set-r6.json、aggregate_protocol_r6.py。
- 健康收集器：acceptance-r6-r2/collector-r6-r2/collect_health_evidence.py。
- 健康原件导出：health-r6-r2-original-export-r1/export_health_r6_once.py。
- 视觉与 Unicode 原件导出：business-r6-r2-original-export-r1/export_business_once.py。
- 视觉与 Unicode 注册：business-r6-r2-root-operator-r1/prepare_register_business_r6.py。
- 原生发送仍使用未修改的 send_new_native_task_r5.py；本包不会自动发送。

## Root 健康执行后的唯一采证入口

健康实际材料目录是 Main 的 health-r6-r2-01，发送标签固定 phone-local-r6-r2-health-01。手机只读来源为 GNU /var/lib/trillionnium/owner-open/phone-local-v150/root-health-r6-r2-01，导出目录为 Main health-r6-r2-originals-01。Root 的 prepare_register_health_r6_r2.py 保持单独封版。

```sh
B='/operator-workspace/razr60/phone-local-v150'
python3 -B "$B/health-r6-r2-original-export-r1/export_health_r6_once.py" capture --execute-read-once
python3 -B "$B/health-r6-r2-original-export-r1/export_health_r6_once.py" collect
```

capture 仅允许一次读取原件。未知或失败必须查看同一原操作；不要重试、删除输出目录或再次发送。非零退出但已有部分原件时保留原件供诊断。

健康资格同时需要完整原件、原采集 actor 与手机进程均为真实整数 rc0、收集器进程为真实整数 rc0，以及原收集器的完整 proof 和 health 谓词。CAPTURE-TERMINAL.json 绑定原操作文件、原 stdout 字节、capture SHA 与两个真实退出码；collect 会再次读取原件核验。raw PASS、部分导出、模型 HTTP200、正确 nonce 或 READY 单独都不是健康通过。

## 健康通过后的视觉与 Unicode

Root 从真实健康终态生成新的 previous input；identity 来自五字段 scope，request_sha256 必须使用原生 envelope digest，不能使用用户文本 SHA。原稿仍由冻结发送器执行准确 CAS 保护及终态后的单独恢复。

```sh
python3 -B "$B/business-r6-r2-root-operator-r1/prepare_register_business_r6.py" visual \
 --combination "$FROZEN_COMBINATION" --combination-sha256 "$FROZEN_COMBINATION_SHA" \
 --previous-input "$VERIFIED_PREVIOUS" --previous-sha256 "$VERIFIED_PREVIOUS_SHA" \
 --execute-register-once
```

Unicode 使用同一入口的 unicode 选项。注册仅创建新材料及 entire_request 一次性合约，不等于发送。Root 独立使用 frozen sender 对新材料执行一次 Send；本包装器无发送功能。

实际发送与终态后，使用现有材料目录和实际标签：

```sh
python3 -B "$B/business-r6-r2-original-export-r1/export_business_once.py" capture \
 --material "$EXISTING_MATERIAL" --sender-label "$ACTUAL_SENDER_LABEL" --out "$NEW_PRIVATE_OUT" \
 --execute-read-once
python3 -B "$B/business-r6-r2-original-export-r1/export_business_once.py" collect \
 --material "$EXISTING_MATERIAL" --sender-label "$ACTUAL_SENDER_LABEL" --out "$NEW_PRIVATE_OUT"
```

业务收集仍使用未修改的 571947 frozen collector，并显式绑定 a8bd 新 source seal。64 MiB 原件和分块归档界限、原 action 回执、原始字节、业务后条件、返回与完整任务终态均保持原门槛。已有 business r2 的手机采集 rc0 / collector rc0 守卫未改变；Root 仍核对每次原 transport actor 退出码。部分完成不提升为整项成功。

## 已完成的 host 验证

16 项 source / metadata 转换均有反向字节证明与独立 diff；未修改生产源码。19 个 case、limits 与 geometry 逐值相等，pending 组合仍拒绝物化资格，空样本仍为 N=0 且 19 未闭合。未运行物化器、未生成 nonce、未执行任何手机或模型请求。

仅针对新健康进程守卫运行一个真实 host 子进程“输出 PASS 后 exit7”的负例，在 actor、phone、collector 三个位置均拒绝资格；positive control 只验证谓词组合，不是手机样本。旧业务 12 项及非零测试不重复，也不冒称为当前实机资格。

源码、diff、公共投影的 source pins 可发布；真实材料、用户文本、截图、草稿、原生历史、运行原件、claims、密钥及完整 policy 二进制不可递归打包。
