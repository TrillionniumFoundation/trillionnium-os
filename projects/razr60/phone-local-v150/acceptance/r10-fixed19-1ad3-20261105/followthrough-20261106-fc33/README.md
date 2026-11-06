# Fixed19 follow-through — checkpoint 3

## 当前结论

本检查点保全了新的 native 候选、安装原件保全实现、实际共享材料派生和一次实机恢复拒绝。**没有新增整项验收通过，也没有将主机控制数换算为 19 项用例通过数。**

当前历史组件仍为 COMBINATION `02c2a26af79e367afe48cb1bc378808f3c5a32800548498a0262ea0265c9f708`。它的原 NEG-01 组件成功证据继续保留；新源码组合必须重新取得相应资格。

## 本检查点新增证据

| 工作 | 已观察到的结果 | 资格边界 |
| --- | --- | --- |
| native v2 | 73 项解析控制、12 条 CodexAdapter.receive → PhoneTools.prepare → 业务门控检查；同 14 个共享业务场景重跑通过 | 无新 native dispatch、手机或模型调用；完整 NEG-11/12/13 尚未关闭 |
| 安装原件保全 | 当前 82 项主机控制、10 项纯绑定构造控制；实际 9,900,047 字节文件经过 12 块完整回读和哈希核对 | 手机观察器、实际 BUILD/phase authority 尚未绑定 |
| 材料发布器 v2 | 18 项目录替换、I/O、完整读回和资源回收控制 | 仅主机输出发布 |
| 真实共享材料派生 | job `1a1b16ec976-fc05-78ae`，exit 0、输出完整；15 源文件、14 个依赖 pin、17 个共享成员及完整对象反演均验证 | COMBINATION `9025ea9c…` 仍是中间材料，尚未 runtime freeze、BUILD、安装或 READY |
| NEG-02 后继恢复 | 实际 binary_write 发布后执行一次，job `1a1b16ac67a-fc05-7887`；主机 exit 0、手机 rc 1 | 首次修改前因旧暂存目录缺失而拒绝，删除数 0；不是恢复成功 |

## Native 输出仍有待补的真实缺口

v2 将返回的 call/tool/target 绑定到已保存的真实映射请求，严格检查事件与终态字段、PID/elapsed 类型、顺序、长度、截断和 canonical base64。原 NEG-01 完整捕获可读，原 guard 70 不会被当作成功语义结果。

v2 尚未在 Python live consumer 独立核对 canonical request digest、configuration fingerprint、generation 的完整性边界和 observation SHA256。Rust 生产者的正常校验不能替代消费者拒绝损坏输出。后续修复须以实际 preimage 和可信请求上下文为准；此处不把 v2 定为最终采用组合。

## NEG-02 恢复记录

本次后继只重绑源码中的三份数据证明。Root 独立解开新旧 XZ，完整反演源码与 targets，确认除实测压缩长度/哈希绑定外启动包装未改；捕获源、scope、nonce、lease、审计目标和预算保持原值。完整 service 命令含 NUL 为 65,214 字节，上限 65,535。

原始 phone stderr 明确记录：

- phase 为 `same_locked_original_capture_preflight`。
- `root-r10-neg02-a1055-final04` 不存在。
- completed_removal_count 为 0，removed paths 为空，durable intent/result 均为空。
- 原先另一条 final02 sender wait 继续为 `UNKNOWN_UNCHANGED`。

另发现此前已经存在的 `ng-a1055-neg02-final04-owned-cleanup02` 原始结果，正在按其完整源码、请求、清理包和事后状态进行独立核验。其结果不改写本次失败，不触发重发，也不在本检查点直接形成恢复资格。

## 目录

- `native-streams-v2/`：59 文件完整候选、基线、diff、主机原件和限制。
- `install-retention/`：43 文件原件保全生产者、读者、构造器与控制。
- `material-builder-v2/`：17 文件安全发布器及 18 项控制。
- `shared-material-v2/`：27 文件实际派生结果与精确引用，另附真实主机 controller 原文。
- `neg02-recovery/successor02-fc33/`：本次实际发布、执行、stderr 和 Root 审查原文；大请求与完整 operation 保留位置见原件清单。
- `STATE.json`、`CHECKPOINT-03.json`：机器可读状态。早期检查点和候选保持原样。

## 下一实际关闭条件

先独立核验已有恢复和手机当前基线，再关闭 native 消费者的完整性缺口，传播最终源码组合到 runtime/history/preparer/BUILD/reader。随后执行同一最终组合的 NEG-01/02、真实 BUILD/install/start/四角色 READY，以及剩余 E2E、COMP 和负例物理任务。所有未知结果保留未知，不自动重放。
