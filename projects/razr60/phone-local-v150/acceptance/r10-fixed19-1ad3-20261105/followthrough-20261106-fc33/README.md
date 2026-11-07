# Fixed19 follow-through — public evidence index

## 最新公开证据入口（2026-11-07）

- [本轮原请求对账与隔离回归](verification-20261107/README.md)：R6 bound01 两次恢复的分别结算、bound02 原 Mac job 的 UNKNOWN 绑定，以及固定源码的本轮可复现回归；不增加整项手机资格。
- [R6 checkpoint10 原状态](checkpoint10/checkpoint10/STATE.json)：保留当时的组合、原始失败和实际派生身份，后续观察单列记录。
- [Host negative results](reviewed-host-source-results-20261107/HOST-NEGATIVE-RESULTS.md)：NEG04/05/06/07/08/09 既有 host runs 的审阅结果与物理层边界。
- [Host negative public summary](reviewed-host-source-results-20261107/HOST-NEGATIVE-PUBLIC-SUMMARY.json)：上述原始 run 身份、结果及完整性映射。
- [NEG10–14 public summary](reviewed-host-source-results-20261107/NEG10-14-PUBLIC-SUMMARY.json)：现有回归与当前 R6 的 15 份源码逐字对应；实际 BUILD、安装及 READY 绑定仍待原件。
- [Source17 remote binding](reviewed-host-source-results-20261107/SOURCE17-REMOTE-BINDING.PUBLIC.json)：17 份材料、387843 字节与精确远端 commit 的完整字节一致性。

这些公开审阅保留原始 run 和历史结果的身份。源码一致性、host 回归与实际部署或手机业务资格分别记账；上述材料没有新增 fixed19 整项关闭。

## checkpoint09 历史记录

以下保留 checkpoint09 当时的记录；其中的“当前状态”指该历史检查点。较新的公开核对见上面的入口。

工作继续，当前最终组合尚无新整项关闭，未宣称19/19通过。

## 已取得的实际结果

final05 recovery02 实际完成，独立主机读取器复核：97文件、10目录、107次有序删除、18最终缺失状态；44个原受保护根、3823项、44,353,573字节完整内容保持，15组锁和实测FD基线收尾。恢复不增加业务或组件用例信用，历史未知监督器wait未升级。

E2E现有49源码和安装控制器27源码已实际发布并完整独立读回。其完整证据包分别64和85个文件；实际BUILD、安装、READY仍未产生。准备的输入模板保持未知值为None。

## 本次实际失败及继续路径

NEG01 bound02唯一新nonce已消费。phone-stage成功，sender-preview成功，发送器公开终态rc2/send0/草稿恢复1，随后sender-prepared等待失败。Root没有启动fixture或模型。底层sender原件和本次新暂存范围仍须独立核对与恢复；不能重放本次身份或将缺回执解释为无效果。

NEG源码source02实际发布也失败，位置为当前完整策略验证器调用原件读取器时的typed descriptor bound。失败原件保留，精确descriptor及半目录诊断继续；没有手机任务、nonce、BUILD或READY。

E2E operator发现phase重复关键字兼容问题，最小修复评审中；原49文件保留，未执行E2E。

所有旧失败、未知和源候选状态快照按原字节保留。公开包没有私有手机result包、草稿、XML和foreign正文。精确当前状态见STATE.json；源码控制记录不能替代实际任务资格。
