# Fixed19 全量推进：检查点 07

当前正式组合尚未新增整项通过。目标仍是把全部 19 项在同一最终组合下闭合；历史成功、源码控制、当前实机结果分别保留其实际范围。

## 当前实际进展

最终 R5 runtime manifest 为 `990c726a1fff139761494cc19cf091deb269201f27ea947dda4a5833e3a72f2a`，组合为 `7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411`。既有失败 bound01 和消费过的 nonce 保留不变；没有重放。

下游 release 源码发布第二次运行成功：精确单行修复只统一 descriptor 顺序，原四份 payload 和完整字节逆向校验保留。第一版写入前拒绝和两个目录实际 ENOENT 的证据仍在。实际发布 binding 8 份、derived 21 份（14 个源码），未执行 BUILD/install/READY。E2E/COMP 绑定器随后实际发布 49 份当前源码；未生成业务身份或调用手机。

后继 NEG-01 bound02 源码已发布并通过实际主机 preview，输出明确为无身份的冻结组合验证成功。它显式排除本次和旧 final05 的已消费 nonce。尚未创建新任务身份，继续等待精确恢复。

## 旧 final05 的新鲜只读证据

完整范围 probe 在手机 exit 0。独立主机导入验证了两个窗口的 44 个原基线根、3,823 个条目、3,495 个文件及每窗口 44,353,573 字节；37 个旧 runtime 成员、61 个 stage 成员、私有树 98 个条目亦完整读取和核对。两个已知进程的完整 proc census 与四次内核 signal-0 检查均得到 ESRCH。claims/operator/actions 为空，fixture 实际 ENOENT。

11 个已知 sender XML 路径的补充只读采集也在手机 exit 0，独立主机私有归档和最终精确清理计划尚在完成。两次 probe 均未输入、调用模型、派发 native 或删除文件；不能据此推断历史效果次数，也不构成清理闭合。核心私有原件已保存在 Pocket4；私有 sender/XML 正文不进入此 Git 证据包。

## 本检查点材料

| 路径 | 内容 | 资格边界 |
| --- | --- | --- |
| actual-source-chain-r5/ | 实际 release source 发布 controller 与完整小原件读回 | BUILD/install/READY 未执行 |
| actual-e2e-source-r5/ | 实际 E2E/COMP 绑定器、输入、controller 与 BINDING 读回 | 业务、模型、手机执行为零 |
| source-publisher-v2/ | 15 份修复和两个实际主机控制，所有 blob 已实际创建 | 单行源码派生修复，无生产源码变更 |
| foreign-final05-readonly/ | 完整范围 probe、公开输入、控制和独立主机核验 | 无删除，无整项资格 |
| foreign-final05-xml-readonly/ | 11 个有限路径的只读 probe 和 controller | 私有 XML 正文不公开 |
| neg10-14-final-source-summary/ | 165 份最终源码主机证据、23 条件映射和实际 blob 回执 | 待绑定实际 sealed BUILD 与安装/READY |
| runtime-r5/successor02/ | 后继源和实际无身份 preview | 新 nonce 尚未生成 |

NEG-14 原协议层为 host_isolated，要求确认 worker/child/file-descriptor 回到实测基线；没有追加 RSS 或真实模型槽门槛。新增四项实际控制覆盖 lstat/scandir errno 13、生产 daily 逻辑字节容量边界、孤儿 intent 保留拒绝和两个自有 child 的原 wait/进程组/FD 收尾。稀疏逻辑容量不冒充磁盘 ENOSPC；各回归组不相加为新测试总数。

## 后续执行

先完成 final05 精确恢复：原 sender host 终态、全部目标、原 44 根和已知进程在持锁窗口重新核对，保留完整原件后只移除归属于该失败任务的有限路径，并独立核验恢复结果。恢复后依次执行新 NEG-01、NEG-02，取得当前组件闭合再 BUILD/安装/READY，随后运行 E2E/COMP 与物理 NEG03–09，最终绑定 NEG10–14。

旧 NEG-01 成功仍只属于原组合。旧 final02 UNKNOWN 不变；旧 final04 清理成功及本次 bound01 失败也不改写。
