# Fixed19 全量推进：检查点 04

当前正式资格仍在推进，没有新增整项 fixed19 通过。历史 NEG-01 的原组合通过保持原值；新的原生输出绑定与五个生产源变化要求在新组合重新取得 NEG-01、NEG-02 和后续业务闭环。

## 已实际完成

旧 NEG-02 暂存恢复已经通过现有公开验证器独立重放：原执行者为既有 cleanup02，77 个文件与 9 个目录共 86 个唯一对象被移除。我们的后发清理仍保留为预检失败、零移除；旧 final02 的未知终态保持 UNKNOWN。完整 inventory 按原 reader 排除 elapsed_seconds 后与 44 根的实际 source-parent 原件一致。

最终 15 个生产源码、17 个共享材料和 38 个组件运行时已派生，并由实际主机冻结进程成功发布。冻结目录共 18,364,398 B；FREEZE-RESULT 为 1,039,896 B，SHA256 d6ae0199011ddb9bfa86d8d0c4b9818e3a9037141f5441e85d43085874fd4a3c。原 controller 成功 exit 0，stdout 1,329 B、stderr 0 B，完整、durable、无重试。此检查点建立时独立 preparer 的全量准入预览已准备启动，终态尚未计入。

新 release consumer 严格要求两个当前成功闭合，再接一个精确 source-parent 和九条原失败祖先。它从两份原始 LEASE 和完整 inventory 推导实际新增根，拒绝同数量替换、乱序、旧身份及原件不一致。旧成功不提供新组合资格。

## 证据位置

- native-streams-v3/：最终生产源、全量差异、实际主机控制和完整原输出归档。
- release-source-chain/：43 项当前派生链控制，包含原失败；不叠加旧 42 项。
- release-consumer-r5/ 与 release-consumer-r5-host-import/：最终源、55 项同组复现、完整初轮失败、接口、实际 Mac 源归档。
- source-worktree/：源码历史扩展、恢复独立原件、R5 差异/清单、冻结器与 preparer 审查。
- actual-shared-v3/：实际 27 文件共享材料及原 controller 记录。
- runtime-r5/：完整 17 文件 delta、实际冻结/绑定源码和 controller、已读小原件。

所有源控制均保留自己的范围与 synthetic 声明，不冒充手机动作、BUILD、安装、READY 或业务完成。下一阶段由根协调器单独运行新 NEG-01、NEG-02，取得真实 LEASE/闭合后继续安装与业务、故障用例。

## 检查点 05：实际前置拒绝已保全

独立 preparer 已全量重读双完成记录、完整冻结目录与输入 full9，实际通过；新的 NEG-01 主机计划仅生成一个 nonce。随后本次 Root 实机链在 phone stage 的 verify_retired 前置校验失败，尚未创建本次组件 home，也未进入 sender 或 Root 夹具阶段。完整 host/phone 原始回执、失败和计划保全在 runtime-r5/current-attempt/。

随后的唯一只读手机观察确认当前父目录为 17 个成员、nlink 19，基线为 16/18；额外成员是既有 root-r10-neg02-a1055-final05。两个别名、两个采样的 full9/names/标签一致，本次 home、journal、fixture 均实际 ENOENT。该新观察用于证明当前差异，不冒充旧失败时点的逐字段记录。

既有 final05 原件显示原组合 lifecycle 在 setup 前失败，sender 报告零 Send 并恢复草稿，但其完整远端角色收尾仍在只读核实。当前保留该任务及其原件，不把它当作成功 source-parent。原 final04 清理闭合仍然成立；新增 final05 足迹是独立的当前前置问题。当前 fixed19 新通过仍为零。
