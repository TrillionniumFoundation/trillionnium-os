# r6-r2 质量检查点02

本检查点只读取、聚合既有原件，没有手机、模型、服务变更或新任务。当前固定19项为 **7 PASS、3 FAIL、9 BLOCKED**。原检查点01的两项真实模型业务任务仍为2失败、0完整成功；一项真实health PASS继续独立计数。新增主机fixture不会改变业务分母。

新增NEG06/14主机层、NEG03组件fixture层、NEG04/05/07/08/09主机层均保留其原始来源和实际进程终态。NEG04/05/07/09仍缺手机层，整项继续BLOCKED。NEG08主机层通过，但手机实际 native/provider cancelled、0工具、HTTP child已join并组消失，原槽位观察仍busy，手机层FAIL；不能把cancelled替成整项成功，也不能以fixture的idle覆盖手机busy。

各层共有15个已执行样本：2个模型业务、11个host_isolated、1个component_direct fixture、1个physical_native_task取消样本。33条声明还保留检查点01的not_run占位记录，33不是执行样本量。业务时延、用量、资源与成本字段直接保留原检查点01；新主机样本的CPU/FD/实际wait及结果原件单列。没有虚构能耗或金额。

Root的最终独立closure已经证明原用户草稿exact恢复、旧服务四组双次消失、原任务和动作没有重放。此安全闭合单列为恢复事件；原取消任务仍cancelled，原slotbusy与physical FAIL没有改写。旧只读观察器327.147秒/334次读取是采证失败耗时，不能作为取消时延。此质量检查点不生成previous，也不授予下一Send；后续新服务仍需独立冻结、启动及原回执门。

五项host ATTEMPTS原引用带有已验证的bytes元数据。聚合投影只去除此冗余键，保留原path+sha256，符合冻结聚合器严格字段集合；投影前后记录哈希和来源均在私有INPUT-PROVENANCE中。原实际结果与151条检查没有变化。

公开材料只含按case/layer的统计、已审摘要和来源hash；请求全文、nonce、草稿、密钥、原生记录及原claim均不发布。
