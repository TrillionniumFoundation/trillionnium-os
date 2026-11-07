# Fixed19：R6 原请求对账与本轮隔离回归

核验日期：2026-11-06（America/New_York）。目录名、原始 job 和证据中的时间戳使用 UTC。

本轮完成原请求身份恢复、两次既有清理的分别结算、固定源码公开回归和13份原生输出原件复核，并产出经本地复现验证的 sender 观察超时修复候选。当前 R6 **没有新增固定19项整项资格**。新的 NEG-01 bound02 仍缺少可核验终态；实际 BUILD、安装、四角色 READY 与物理业务证据没有被这些主机结果替代。

固定仓库提交为 `ca3f26100c57579bcb740488e4a7f9ec8b912e4d`。本目录追加证据与隔离候选，不修改冻结生产源码、manifest、旧 nonce、旧失败或全局 machine authority。新候选尚未采用到 R6。

## 1. 先前清理成功与后发拒绝已经分别结算

共同范围是 `root-r10-neg01-fc33-r6-bound01`，原 nonce 为 `5f94c6a88805eefb0e2320cae5265d46`。

| 原始操作 | 较早 recovery02-fresh | 后发 recovery02 |
| --- | --- | --- |
| Pocket4 job | `1a1b33a7191-fc05-813f` | `1a1b3426151-fc05-8186` |
| 外层进程 exit | 0 | 0 |
| 手机 rc | 0 | 1 |
| 原独立 reader | `1a1b33b9725-fc05-814c`，exit 0 | `1a1b3456b55-fc05-81a2`，exit 1 |
| 已验证删除 | 67 文件、9 目录，76 个有序事件 | 0 文件、0 目录、0 次效果尝试 |
| 锁与 FD | 14 把锁关闭，FD 回到 `0,1,2,3` | 14 把锁关闭，FD 回到 `0,1,2,3` |
| 结果 | 原限定范围的 owned recovery 已闭合 | `PRE_MUTATION_REJECTED` |

后发请求在 `complete_original_preflight` 因 `exact staged home in actual private shared parent` 拒绝。外层 exit 0 仅说明包装进程结束，不能覆盖手机 rc 1。后发拒绝没有撤销此前独立验证过的67文件、9目录清理。

较早 reader 的完整报告核对了44个受保护根、3,823个条目、44,353,573文件字节的完整基线投影。实际 reader 源码已只读检查，933,670字节 actor result 的当前完整文件指纹仍与原 reader 绑定相同；本轮没有再次完整导入全部私有 actor result 并重跑独立验证。后置库存以完整投影及 hash 表示，未声称存在另一个 raw after-inventory 文件。

原始 status/read、完整公开报告、读取范围和限制保存在 [recovery/README.md](recovery/README.md)、[SUMMARY.json](recovery/SUMMARY.json) 与 [完整性清单](recovery/ARTIFACT-INTEGRITY.json)。这些是本轮对既有执行的对账，不能描述为本轮再次删除了这些文件。

## 2. 当前 UNKNOWN 已绑定到正确的原 Mac job

| 字段 | 当前已核实值 |
| --- | --- |
| 原 controller host | `mac` |
| Job | `1a1b3420986-fc05-8183` |
| Label | `root-r10-neg01-fc33-r6-bound02` |
| Nonce | `731dc46ccaad6e5717306d0c5f029a82` |
| 原 metadata launch state | `launch_unknown` |
| ROOT-PLAN SHA256 | `0fbfd5aa0ed86e0bad846f2e541c3117ee1c7a46c98af7000c96f2e7d25a4bfa` |
| 当前 status / log 查询 | 原 worker job 目录不存在，两个查询均返回错误 |

原 controller metadata 的 executable、完整 argv、plan 路径和 SHA 与唯一已生成计划完全一致。计划的 `ONE_NEW_COMPONENT_PLAN_PREPARED_NO_PHONE_EXECUTION` 只描述准备阶段，不能覆盖后续 controller 的 `launch_unknown`。

沿冻结 root 源码推导的两个精确 Pocket4 原路径——nonce 对应的 chain 目录与 label 对应的 sender 目录——本轮只读查询也均返回不存在，原回包保存在 [BOUND02-PATH-OBSERVATION.PUBLIC.json](BOUND02-PATH-OBSERVATION.PUBLIC.json)。这些缺失没有提供原请求的可核验终态。

缺失 job 或执行目录不是从未执行的证明，也不是成功、失败、取消或零效果的终态回执。本轮没有用新 key、nonce 或重启同一 argv 重派该任务；也没有取消其他会话的任务、向其他执行会话发消息或修改手机状态。

查询的脱敏副本与脱敏 metadata 见 [CONTROLLER-RECONCILIATION.PUBLIC.json](CONTROLLER-RECONCILIATION.PUBLIC.json)。两份原错误文本各移除一处配置的 SSH target，逐项保留原文本长度、SHA256、公开文本 SHA256 及脱敏路径，错误和 UNKNOWN 原义不变。[独立字节与身份核对结果](CONTROLLER-RECONCILIATION-REVIEW.json)保留原完整材料的 SHA256；私有幂等 key 与配置的 SSH target 不在公开材料中。

## 3. 当前15份生产源码的公开回归已实际执行

本轮按固定 GitHub commit 取得45个文件、35个唯一 blob、954,381字节。导入时和运行后均核对长度、SHA256及 Git blob；变化数为0。实际被测15份 candidate source 与现有 R6 的15份 production material 逐一一致。

R6 组合保持为 `7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411`，runtime manifest 为 `270357b7649af61414d31580b3c1eaddc47174bd1bac3c8adfc02934a92c8cf5`。17份共享材料、387,843字节的既有远端绑定继续有效；该绑定不证明当前已安装或 READY。

| 本轮独立 run | Exit | 结果 |
| --- | --- | --- |
| `selected-guards-01` | 0 | 13项图像、文件系统竞态、未知 I/O 和资源控制通过 |
| `shared-business-01` | 0 | 14个业务完成条件／身份绑定场景通过 |
| `native-public-fixtures-01` | 0 | parser 73、consumer 12、trust parser 40、trust consumer 11、dispatch binding 9，各组通过；ledger binding通过 |
| `native-require-actual-01` | 1 | 明确拒绝公开包中缺失的私有实际原件；该失败保留 |

以上组别不与历史 run 或彼此重复运行相加成新的总用例数。四个 run 各有独立 output 和原始 stdout/stderr，均未超时；FD、线程集合前后相同，子进程 CPU 计数均保持0。未宣称 RSS 回到基线，也未增设 RSS 或模型槽位验收门。

这批回归 phone calls、model requests、native dispatches 均为0。公开 fixture 的通过不覆盖 `--require-actual` 对13份原 native 成员和精确 schema 的要求，也不覆盖真实截图、模型决策、手机输入或返回条件。

机器结果见 [RUN-SUMMARY.json](cloud/RUN-SUMMARY.json)，来源对照见 [SOURCE15-R6-COMPARISON.json](cloud/SOURCE15-R6-COMPARISON.json)。[原始 run 归档](cloud-host-regressions.tar.gz)含908个文件、2,514,217原始字节；[逐文件清单](CLOUD-ARCHIVE-MANIFEST.json)已通过完整解包字节核对。原源码直接引用固定提交中的公开 native-v3 包，未将私有原件加入该归档。

## 4. 实际原件复核与导航依赖

### 4.1 要求真实原件的追加 run 已通过

从固定公开来源指向的精确 operator 路径只读取得16,924字节 schema 与13份原件，共569,919字节成员；逐个完整 SHA256 均与原 schema 相符。大文件同时核对分段 hash 和固定版本，没有声称跨文件原子快照。

在独立副本中，以原样测试入口运行新的 `native-require-actual-retained-01 --require-actual`，exit 0，实际原件状态为 `READ_ONLY_ACTUAL_ORIGINALS_VERIFIED`。原 capture 及 guard 的 preimage 和完整回执匹配；原 guard exit70 仍被当作失败结果，未改写为业务成功。输入前后不变，stderr 为0，未超时，已等待原测试子进程结束，FD／线程／子进程CPU回到本次实测基线。

这个追加 run 关闭了本轮 archived-original parser／consumer 复核缺口。最初公开副本缺原件的 exit1 原样保留；原970个证据成员、manifest 与 RUN-SUMMARY 再次核对未变。两次运行不合并成一条成功历史。

[公开摘要与13份成员描述符](actual-originals/ACTUAL-ORIGINALS-RECHECK.PUBLIC.json)只包含允许公开的计数、长度、hash 与结论。完整 schema、成员、传输分段、实际 RESULT 和日志没有加入公开归档。这仍是当前相同15份源码读取历史原件；没有新手机观察、业务重放或固定19项整项资格，也没有替代 BUILD／安装／READY 绑定。

### 4.2 导航控制与实际 helper 已核实

17项本地导航控制通过，覆盖准确 launch、Activity、focus、top-resumed，以及错误、重复或缺失字段的拒绝。新 portable runner 在导入前核对四份固定源码的长度和 SHA256，并执行同一份已核对内存字节；源不符和旧输出覆盖两项入口控制也通过。

实际外部 UI helper 已完整取得并匹配 sender 内嵌 pin；下一层24,731字节 socket／route helper 与现有仓库原件匹配。精确旧 sender 的 dump137 失败流控制确认一次调用、保留 rc137、零成功 dump 回执。137来自退出通道；实际被终止的进程与原因仍为 **UNKNOWN**，本地 socket 关闭不能证明远端进程组清理。

同时复现了一项独立缺陷：旧 helper 的 timeout 只限制每次 socket 等待，持续小数据会超过整体观察预算；本地0.2秒预算控制约0.405秒仍成功。隔离候选把同一 monotonic deadline 贯穿 shell 入口、route、connect、send、handshake 与逐帧读取。5项 socket 控制与2项完整 route 路径控制通过：慢数据／静默约0.201秒超时，成功与137保留，route耗尽时零shell请求。

该候选保持数值预算、线协议、路由和重试次数；它不是严格实时调度保证，不证明远端收尾，也未给独立的旧 `route(c)` 或整个 actor 增设总 deadline。它与实机137的因果没有建立联系，未修改 R6 pin 或执行任何手机任务。完整公开运行依赖仍未闭合：精确 helper 的 runtime config 没有本次读取或绑定。

见 [依赖与修复说明](navigation/SENDER-DEPENDENCY-REVIEW.md)、[隔离候选补丁](navigation/candidate/SHELL-DEADLINE.patch)、[可复现导航入口](navigation/check_navigation_source_v2.py)及[23份审查材料完整性清单](navigation/ARTIFACTS-v2.json)。所有计数均为源码控制，不与产品固定19项相加。

## 5. 固定19项当前关闭边界

| 用例 | 本轮之后的准确边界 |
| --- | --- |
| E2E-01 随机视觉挑战 | 当前组合的截图入本地模型、一次选择、挑战码回执及返回仍待原业务回执 |
| E2E-02 中文／emoji／换行 | 历史成功保留；当前组合完整输入、确认、逐字读回、公开回执及返回待验证 |
| E2E-03 计算器 | 当前组合的新随机表达式、真实可见结果、独立计算及返回待验证 |
| E2E-04 设置版本读取 | 当前 UI 字段、唯一 view、包与焦点的原件待取得；未修改设置 |
| COMP-01 显式返回 | 源码检查与独立控制支持精确 launch／Activity／focus／top-resumed 验证；完整实机返回待验证 |
| NEG-01 焦点变化拒绝 | 既有组件通过证据保留；纳入当前正式组合的 R6 bound01 在 Send 前因 dump137失败，bound02 保持 UNKNOWN |
| NEG-02 内容变化拒绝 | 已有清理按原 scope 结算；当前组合仍需同 viewport／focus 下内容改变、input前 exit71 的原证据 |
| NEG-03 外屏／旋转拒绝 | 当前完整物理任务资格待补；本轮没有注入输入 |
| NEG-04 dispatch前断连 | 既有主机隔离层通过；当前组合物理任务层待补 |
| NEG-05 效果开始后断连 | 既有主机隔离层通过；物理任务层的至多一次与未知状态保持待补 |
| NEG-06 模型超时 | 既有合成模型超时、worker收尾与零派发主机证据保留；实际部署绑定待补 |
| NEG-07 执行器结果超时 | 既有主机迟到结果不改终态通过；物理任务层待补 |
| NEG-08 dispatch前取消 | 既有主机层通过；物理任务层零效果及收尾待补 |
| NEG-09 首次效果后取消 | 既有主机层通过；物理任务层保留首次效果、不继续输入或强制返回待补 |
| NEG-10 图像预算／过期／旧round | 当前15源公开回归通过；实际 BUILD／安装来源绑定仍待原件 |
| NEG-11 native输出损坏 | 当前 parser／consumer／trust组及13份历史真实原件复核通过；不自动增加物理资格 |
| NEG-12 部分任务冒充完成 | 业务完成条件回归通过；实际 BUILD／安装来源绑定仍待原件 |
| NEG-13 模板并发／旧nonce | 绑定与重放拒绝回归通过；当前安装与真实执行绑定仍待原件 |
| NEG-14 容量／rename／资源收尾 | 当前图像／文件系统／资源回归通过；两次清理的锁、FD与删除结果分别保留，未合并为整项通过 |

下一执行必须沿原 Mac job 恢复可核验结果或形成原请求的正式恢复结算，然后由唯一设备执行入口取得当前 owner、boot、锁、策略、端点与库存的新鲜一致证明。实际 BUILD、安装和四角色 READY 经既有 reader 接受后，才能绑定当前源码回归，并进入同一组合的各原业务与物理负例。所有历史 UNKNOWN 和失败继续保持原义。
