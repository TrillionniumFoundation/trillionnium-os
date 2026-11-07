# RAZR60 候选采用和 CI 记录

取证时间：`2026-11-07T05:41:30.504Z`。本记录只选择源码审阅基线；实际安装、执行资格和 fixed19 通过数不由本记录产生。

## 采用决定

选定 PR #112 的 `22e6105c2effe102c0f120a906752003aedfb37d`、Git tree `019ac4d3e59b2a3b77f71a340d3fe2d368b5b524` 作为后继候选准备的唯一源码与证据基线。父提交为 `ca3f26100c57579bcb740488e4a7f9ec8b912e4d`。PR112 仍为 open/draft；没有把该提交或 deadline helper 采用到冻结 R6。

下一观察链候选使用 helper SHA256 `06cab5903387dd10c29ea6fbddb6e4f4e6ceb6e2e3e835de1148619d89e139e0`，25791 字节。独立 socketpair 复现显示旧实现以 0.2 秒预算成功返回时实际耗时 0.400884 秒；候选在 0.200530 秒超时。5 项 socket 控制和 2 项完整 route 路径控制通过。全部是本地 fixture，未连接 ADB daemon，未调度手机任务。

## PR 角色及进入 112 的文件来源

以下对比使用每个 PR 的完整 changed-filename 列表及两侧非截断完整 Git tree，检查路径、blob、type 与 mode。它证明源码内容身份，不证明安装或运行采用。

| PR | Head | 角色 | 变更路径与 112 的关系 |
| --- | --- | --- | --- |
| [#104](https://github.com/TrillionniumFoundation/trillionnium-os/pull/104) | `2541c380f3f718803983c918f6a20793479c1127` | v149 CLI/Provider 身份绑定 | 55/55 同路径同字节 |
| [#105](https://github.com/TrillionniumFoundation/trillionnium-os/pull/105) | `c3f10ff04485b4d365572ef0fff8495d2daf4d16` | 文档资格及 email-autolink 解析修复 | 14/17 同路径同字节；3 个后续累计入口变化 |
| [#106](https://github.com/TrillionniumFoundation/trillionnium-os/pull/106) | `fed5452e8a94939c6d88bc24c47844b37f8f7368` | r8 transport/ownership/deadline 包 | 25/28 同路径同字节；3 个后续累计入口变化 |
| [#107](https://github.com/TrillionniumFoundation/trillionnium-os/pull/107) | `8cccf753229eb53d666a6eae5a330552a2d110cc` | Host transport 源码候选 | 10/13 同路径同字节；3 个后续累计入口变化 |
| [#108](https://github.com/TrillionniumFoundation/trillionnium-os/pull/108) | `653ce1942c3c7d1d3faa1260b53765dd082f32fb` | native/capacity、审计输出、recipe、取消及 epoch-v2 独立候选 | 202/202 原路径未进入；62 个 blob 在其他 archive 路径找到，140 个在整个树无相同 blob |
| [#109](https://github.com/TrillionniumFoundation/trillionnium-os/pull/109) | `75cb48b0098664f68d19dbb878a3a902a5a6c3b0` | HTTP 观察预算与 owned-sender drain | 22/25 同路径同字节；3 个后续累计入口变化 |
| [#110](https://github.com/TrillionniumFoundation/trillionnium-os/pull/110) | `a98aff68ea3f7277272cfa2bf9df02454a3b05fe` | 109 + 106 的双亲源码整合 | 15/15 同路径同字节 |
| [#111](https://github.com/TrillionniumFoundation/trillionnium-os/pull/111) | `ca3f26100c57579bcb740488e4a7f9ec8b912e4d` | R6 源码整合、checkpoint11、fixture 同步及 shared17 记录 | 94/94 同路径同字节 |
| [#112](https://github.com/TrillionniumFoundation/trillionnium-os/pull/112) | `22e6105c2effe102c0f120a906752003aedfb37d` | 当前核验基线：bound02/recovery 分离与 socket deadline 候选 | 112 为当前比较目标；相对 111 为 93 个新增原件/源码文件 + 1 个 README 追加 |

#108 必须作为独立未采用候选保留：其 head `653ce194…` 与 #111 head 在 Git 中 diverged，merge-base 为 `a87b2fc4…`；不能宣称已全量合入 #105–#110。树中无独立 blob 的结论没有扫描压缩档内部，不等同于证明所有 private archive 中都不存在。CPU cancel coordinator、epoch preparer 和 source recipe 的新源文件没有按其发布路径进入112，需逐项兼容与必要性审阅后才能选择。

#105、#106、#107、#109 的非同字节项均是后续累计的 PUBLISH-MANIFEST、PUBLIC-PROJECTION-INDEX、项目 README 或 publication test。每个精确 blob 记录在 `PROVENANCE-COMPARISON.json`，不将累计文件误写成原版本字节不变。

17 项生产源/配置/服务材料已从 112 重新完整读回，共 387843 字节；重新计算长度、SHA256 和 Git blob SHA 后，全部与已有 R6 shared17 binding 一致。原件和独立结果在 `shared17-fresh-readback.json`。这仍不替代 actual BUILD、安装字节读回或四角色 READY。

## 当前 Head 的 CI

检查库存显式使用 `filter=all`，保留全部旧 attempt；下表不能与默认只返回最新 attempt 的历史数量直接比较。特别是 #107 的 34 项比旧记录的 20 项覆盖范围更大，并非发现 14 项新失败。完整失败原始日志全部留存，未重跑。

| PR | success | failure | cancelled | 判定 |
| --- | ---: | ---: | ---: | --- |
| #104 | 11 | 1 | 0 | PR 聚合拒绝：integration branch is not protected |
| #105 | 24 | 1 | 0 | PR 聚合拒绝：integration branch is not protected |
| #106 | 19 | 1 | 0 | PR 聚合拒绝：integration branch is not protected |
| #107 | 23 | 5 | 6 | 当前 PR 聚合未保护；另保留历史 required-upstream cancelled 导致的聚合失败 |
| #108 | 10 | 10 | 0 | LICENSE email-autolink 解析拒绝；synthetic parent-identity guard 拒绝；下游聚合拒绝 |
| #109 | 19 | 1 | 0 | PR 聚合拒绝：integration branch is not protected |
| #110 | 19 | 1 | 0 | PR 聚合拒绝：integration branch is not protected |
| #111 | 19 | 2 | 7 | 原 PR 聚合未保护；另一次 push 上游全部 cancelled 导致聚合失败 |
| #112 | 19 | 1 | 0 | PR 聚合拒绝：integration branch is not protected |

PR112 全事件共有 8 个 workflow runs，均 attempt 1；7 success / 1 failure。全部 20 个 checks 为 19 success / 1 failure。失败原件为 [run 42322594887 / job 128256247799](https://github.com/TrillionniumFoundation/trillionnium-os/actions/runs/42322594887/job/128256247799)：五个 source jobs 均成功，聚合器 34 项控制通过，但 live gate 明确返回 `integration branch is not protected`，exit 2。同名 push aggregate 的成功不能覆盖该 PR 失败。

实时分支查询确认 integration base `codex/razr60-r6-source-integration-20261106` 指向 `ca3f2610…` 且 `protected=false`；repository rulesets 为 `[]`，PR112 formal reviews 为 `[]`。本轮没有修改保护、required checks 或审核要求。对取消仅记录已有取消结果，不将取消原因猜成资源不足或平台故障。#108 父身份 guard 日志未回显不匹配的 tip，保留这一边界。

## 下一执行锁

原 bound02 必须先由既有流程接受权威终态或处置；之后才有 fresh single-owner admission。候选文件、配置原始字节、实际 wrapper、完整 runtime graph、预算、REQUEST/PLAN 和 owner 需要一同冻结。修改 socket helper 必须沿 UI helper 的直接哈希和 sender/runtime wrapper 继续级联，不能将业务 sender `f90c6ffb…` 冒充实际 runtime sender `de6c9018…`。旧组合 NEG-01/02 成功不能计入新组合。

原 `137/Killed` 原因仍 UNKNOWN。候选只约束本地 shell 观察预算；关闭 socket 不能证明远端进程树已结束，也没有建立整个 actor 的硬时限。bound02 的未知状态没有因此改变。

附带只读 GitHub inventory job `1a1b4812f28-fc05-87e3` 返回 `launch_unknown`，原 status/read 又返回 job-directory FileNotFoundError；未换 key 重跑，未将缺目录解释为未执行。该 job 只包含 GET 查询，与手机运行无关，CI结论使用 GitHub connector 直接证据。

机器可读材料：`CANDIDATE-ADOPTION.json`、`CI-CHECKS.json`、`PROVENANCE-COMPARISON.json`、`TREE-INPUTS.json`、`shared17-fresh-readback.json`、`fresh-timeout-result.json`、`fresh-route-result.json`。
