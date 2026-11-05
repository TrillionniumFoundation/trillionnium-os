# Fixed19 checkpoint04 — post16 与下一阶段源码交付

## 当前资格

主机隔离层 NEG04、NEG05、NEG07、NEG08、NEG09 的 5 项检查已在 checkpoint03 留存真实通过原件。本轮不重复发布这些原件。固定19项的整项合格数仍为 **0/19**；这些主机结果不代替物理层。

实际独立 post 比较已经完成 **16/16**：原始比较耗时 **339.780211539 秒**，退出码 **0**，未超时，输出完整，输入原件前后相同。控制器原作业为 `1a1aad877de-fc05-4800`，stdout 833 字节、stderr 0 字节，状态与原始 read 逐字节一致。原报告、外层执行记录、子进程记录、controller status/read 均保留在 `actual-live02/post-independent/`。

实际导出的策略为 `f8219f9c3ad2e1d16a95fda8d5f0bc7612a31e00c0a661e53bf9a6e921c49d70`，2667740 字节。本 checkpoint 没有声明 adoption、实际 R8 freeze、安装、READY 或任何物理用例已经完成。

既有 workflow 的 collector 也已留下 `COMPLETE` 原结果及容量原件，三份小记录保存在 `actual-live02/post-independent/archive/`。完整归档为 **42,908,438 B / ca42b7d9…**，继续保留在原 P4 路径，本 checkpoint 不复制其大二进制。small packet 为 **874,243 B / d50a016f…**，容量记录列出 **193 个路径描述符、125 个唯一对象、2,476,074 B 唯一原始内容**。这里仅核这些原记录与同一 post 报告的链接；还没有读取完整 proof index 来重新累计全部路径字节，也没有声明 mirror 或 adoption 完成。`SOURCE-RESULT.original.json` 是源码准备记录，其 `collector_executions=0` 不被改写成执行记录。

## 实际消费身份

完成的 retention 使用 **d960f6ba… / 22408 B** 原源码，其未来主机传输仍是 **860aaf74… / 43438 B**。`ACTUAL-RETENTION-RESULT.original.json` 与实际源码快照明确证明这一身份。

本轮准备的 **f6d8d7ec…** 0374 retention 修复，以及已绑定实际 inputs 的 **6193646f6b12d2a720a9086423aebcd7d914a3ff9d799edf7a86fe17f8d10758 / 22498 B** 候选均未被本次实际 retention 消费。它们是后续候选，不能用这次 post16 成功宣称其 transport 已经执行。0374 mirror 候选 **e2ba3f8e…** 和准备器 **10067a44…** 也分别保存。

实际应用源码 **5cd18af1…** 保持原件身份。它的真实角色顺序拒绝及 traceback 原样留存；独立 host verifier **74f4c89b…** 是另一个显式源码身份，不能把它的成功改记为旧5cd通过。

## 交付范围

| 目录 | 范围与限制 |
|---|---|
| `component-physical-final02/` | 完整原包、原 tar、40 项本地验证及其原件；真实组件/旋转用例 0 次 |
| `r8-freeze-preparer-final01/` | 完整原包、原 tar、单 FINALIZATION RHS 构造器及10项本地检查；实际 freeze 0 次 |
| `cpu-cancel-compat-candidate01/` | 按 SOURCE-MANIFEST 的全部声明成员保存，未来依赖未冻结 |
| `six-host-preparer/` | 665b 准备器，真实 cascade 输入仍须实际绑定 |
| `post-evidence-preparation/` | 10067 helper、e2ba mirror、f6d8 retention、6193实际绑定候选与派生/patch |
| `independent-host-verifier74f4/` | 四个现用源码、四个父源码、原 MF、已缓存 patch/interface；明确是局部原包快照 |
| `independent-post-v2/` | 五个比较源码和 collector/mirror/retention、原 MF及已缓存patch；五个比较源码pin全部核对 |
| `actual-live02/` | 原5cd失败诊断、v2 live provenance、actual d960 retention及post16原件 |
| `reviews/` | 本轮对应范围的本地与独立审查，不作为物理通过证明 |

完整组件、R8准备器及CPU候选的原清单闭集逐成员核验。两个外部源包的原清单还声明了 **17 份**未在当前本地缓存中的派生或失败记录；没有伪造、重构或删除它们。`CHECKPOINT04-MANIFEST-COVERAGE.json` 逐项列出原始描述符、已收成员与缺件，因此不会把这些快照称作完整外部包。所有已收源码都按原清单SHA核对；原清单字节保持。

## 发布与复核

`PUBLISH-INDEX.json` 使用 checkpoint03 的同一行格式，逐文件提供仓库路径、本地文件、字节数、SHA-256、Git blob SHA-1，以及 `utf-8`／`base64` 编码。二进制的本地 `.base64` 旁件仅供上传，不作为额外仓库成员。索引本身不参与自身散列。

`CHECKPOINT04-PROVENANCE-MAP.json` 记录每份发布文件的本地来源；`CHECKPOINT04-DELIVERY-VERIFICATION.json` 记录读取、闭集、tar原字节及真实post链接核对。此目录只是本地交付，未推送Git、未访问远端、未操作手机。全部既有执行预算保持，失败历史继续保留。
