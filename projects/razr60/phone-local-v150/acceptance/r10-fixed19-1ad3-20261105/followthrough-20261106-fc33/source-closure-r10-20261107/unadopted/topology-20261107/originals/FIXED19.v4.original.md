# 固定19项原件库存：独立清理闭合与后续失败并列追加

原37条attempt与此前两恢复事件逐字段保持；本次追加cleanup02独立宿主闭合事件及primary660f-cleanup-74ec原始失败事件。新增fixed19资格为0。

cleanup02完整operation为6,151,995字节，SHA-256 9bae925fe62ad40039b1b915d309c14c1d58a5f36067ad4d1b77fae719fe6fd0。独立消费者已核验同nonce清理闭合；完整结果记录62个私有stage文件、4个transport文件、11个sender XML文件及9个目录；canonical inventory视图由46根到44根，另有两份新增审计原件位于44根之外。该闭合仅适用于已声明的owned-stage及归属transport/XML范围，不代表全机只剩44项。

后续primary660f-cleanup-74ec使用stdin结果schema，phone.exit_code为1；原件预检FileNotFoundError，删除列表空、intent/result为null。这项失败单独保留，不覆盖cleanup02闭合，也不推断无效果。

readonly codec原件证明固定stdin解码后未执行mutator，作为辅助原件保存，不计资格。旧UNKNOWN、unconfirmed、历史组合范围及原NEG02组件未闭合状态均不改写。

| Case | 必需层 | 已扫描记录 | 当前所选请求 | 当前组件闭合原件 |
|---|---|---:|---:|---:|
| E2E-01 | model_e2e | 1 | 0 | 0 |
| E2E-02 | model_e2e | 1 | 0 | 0 |
| E2E-03 | model_e2e | 0 | 0 | 0 |
| E2E-04 | model_e2e | 0 | 0 | 0 |
| COMP-01 | component_direct | 0 | 0 | 0 |
| NEG-01 | component_direct | 22 | 1 | 1 |
| NEG-02 | component_direct | 1 | 1 | 0 |
| NEG-03 | component_direct | 1 | 0 | 0 |
| NEG-04 | host_isolated, physical_native_task | 1 | 0 | 0 |
| NEG-05 | host_isolated, physical_native_task | 1 | 0 | 0 |
| NEG-06 | host_isolated | 1 | 0 | 0 |
| NEG-07 | host_isolated, physical_native_task | 1 | 0 | 0 |
| NEG-08 | host_isolated, physical_native_task | 1 | 0 | 0 |
| NEG-09 | host_isolated, physical_native_task | 1 | 0 | 0 |
| NEG-10 | host_isolated | 1 | 0 | 0 |
| NEG-11 | host_isolated | 1 | 0 | 0 |
| NEG-12 | host_isolated | 1 | 0 | 0 |
| NEG-13 | host_isolated | 1 | 0 | 0 |
| NEG-14 | host_isolated | 1 | 0 | 0 |

范围：Exactly the existing direct r10 native request families, old r7-r3 ATTEMPTS array, named current source handoffs and current captured cleanup event originals. Other request registries are not asserted complete.

新增扫描只覆盖明确列出的cleanup02完整三原件、原包12成员、独立consumer/closure/原始caller证据、primary失败与readonly codec原件；未宣称全部磁盘历史已扫描。当前live owner/锁/endpoint、正式生产组合、四角色READY及新NEG02仍需各自准入。
