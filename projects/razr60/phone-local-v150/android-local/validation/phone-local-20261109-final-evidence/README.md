# Code19 后续证据与 LiteRT-LM 研究

本批只追加经过审阅的公开摘要和官方技术研究。它保留各次运行的原始结论，应用源码仍是已冻结的 Code19，完整手机验收尚未通过。

## 后续七项测试

[独立核对说明](remaining-seven/PUBLIC-SUMMARY.md)与[机器可读摘要](remaining-seven/PUBLIC-SUMMARY.json)记录后续七项的最终结果：**3 项通过、4 项失败**。77 次 native 调用中，74 次完整完成；75 次有正向 HTP 证据，其中完整完成的 74 次都记录 43 层。不能将这些数字表述为 77/77 次完整推理。

本轮 `final_evidence_qualified=false`。默认网络连通性检查为 false，主机退出码没有确认，资源监测被停止标记结束，尾部相差 2106 ms。这些边界与各 case 的严格结果分别记录，未通过删除条件或改写空值消除。

最初九项运行仍保持 [1 pass / 1 unknown / 7 not_run](../code19-retained-phone-evidence/interrupted-suite/PUBLIC-SUMMARY.md)。其第二项的迟到补证没有改写原 unknown。后续七项及其统计是独立的一次续测，不能拼成一轮完整、连续离线并通过的九项验收。

## 失败原因与停止流程

[导航因果分析](navigation-causal-audit/PUBLIC-SUMMARY.md)保留 find、scroll、cross-app 三项的逐项边界：find 仅查询、没有打开目标且方法来源记录被历史预算裁掉；scroll 有真实页面变化而后段历史被裁空；cross-app 保留历史后仍反复选择错误的文字替换。这里没有把所有失败统一归为模型能力或单一控制器问题。此前的[计算器因果证据](../code19-retained-phone-evidence/calculator/PUBLIC-SUMMARY.md)保持原样。

[停止与低内存中断说明](stop-low-memory/PUBLIC-SUMMARY.md)记录停止测试未能验证点击、应用进程被 LOW_MEMORY 回收及原 native 清理状态未知。普通打开随后由应用正式归档旧 journal，进入 interrupted / blocked；它没有恢复旧任务。Code19 界面缺少用户确认后建立新会话的恢复入口。这份记录不把进程消失当作原 native 的完整退出回执，也不把本次 Stop 测试记作通过。

## LiteRT-LM v0.19.1 独立研究

[ADDENDUM.md](litert-lm-v0191/ADDENDUM.md)补充最新官方 LiteRT-LM、Gemma 4 GPU／NPU、MTP、结构化工具输出与取消机制的源码研究。对应[来源索引](litert-lm-v0191/SOURCE-INDEX.json)和[上游身份](litert-lm-v0191/UPSTREAM-IDENTITIES.json)一并保存。

这三份文件属于研究证据：没有下载新的模型权重、没有编译新的 LiteRT 运行时、没有运行模型或接触手机。所提下一实验不代表本机已有性能或任务通过结果。既有[中文技术记录 v5](../code17-build-and-qualification/phone-regressions/RESEARCH.zh-CN.md)保持原字节，新增研究与后续事实由本目录单独补充。

## 源码与 CI 身份

应用源码仍由完整 866 成员 manifest
`9817f2af3937a402b52176565233c763869495d203080deffd7e279f9f621b69`
绑定，版本仍为 Code19；本批没有修改源码、模型配置、测试目标、私有手机原件或此前 40 份公开文件。两个尚在主机研究中的候选没有进入本批提交。

本批父提交 `64c0612017eb019984e1e16872c0d60015f04da2` 的六条 PR workflows 已实际成功，关键回执为：

- [G1 exact-head source qualification](https://github.com/TrillionniumFoundation/trillionnium-os/actions/runs/42589565591)
- [G1 synthetic-merge qualification](https://github.com/TrillionniumFoundation/trillionnium-os/actions/runs/42589565557)
- [Hepta local Android candidate](https://github.com/TrillionniumFoundation/trillionnium-os/actions/runs/42589565679)

父提交的成功不代替本批新 head 的 CI，也不构成手机普通入口、停止、生命周期或完整离线任务资格。PR 保持 draft，目标仍为受保护的 integration 分支，未合并。

逐文件身份见 [PUBLICATION-MANIFEST.json](PUBLICATION-MANIFEST.json)。原始手机 UI、任务标识、私有路径、截图和完整审计输入均未纳入本批。
