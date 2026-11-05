# Checkpoint08 — 原生构建与17份材料完成，全项验收仍0/19

本次追加在 d01040f83c12f0fa9b6f3477d5ad2bec54c54d1b 之后，保留此前全部检查点与失败。用户要求的 E2E01–04、COMP01、NEG01–14 共19整项仍为 **0/19**。主机层 NEG04/05/07/08/09 的5/5及 policy post comparison 的16/16仍分别列账，不升级为物理或业务通过。

## 实际完成

- 原生 bounded-output build02 在真实Mac完成四条原编译命令，sidecar965952字节/21b59e78…，worker296096/49fb74f8…，完整host结果33309/263fec44…及所有15输出原件已核验。原先缺头文件build01与stage04首次失败完整保留。尚无新二进制手机运行资格。
- 新17材料由同一最终builder的material-only路径实际生成，job 1a1ad738dfb-fc05-59ed rc0、完整durable、4806字节stdout/0stderr、双EOF。四个production源码改动、服务清单及配置与预固定候选逐字一致；SHARED-MATERIALS.json为3519字节/cbf97ec9…，19输出已全量读回。初次basename门失败及修正后的create-only原名staging完整保留，未放宽原守卫。
- 新sidecar路径对应三个module source修订已在Mac独立路径create-only保存并全量读回。旧11 module字节及旧artifact路径保留；phone未部署。
- legacy902的boundary/inventory/closure三个Mac carrier已完整读回，923078字节inventory包含固定版本分块与两次RPC超时后的原operation恢复。所有原失败记录保留；不是新phone调用。
- extra2 homes只读观察完成并保留全部原件、两轮正文和别名物理双计。
- fullfrontier505实际观察停在/proc/1/net/unix元数据不一致：第一轮946个stat原件与116个静态正文保留，但无第二轮census、无静态末尾身份检查、无全局endpoint clearance。它发现的6077失败分支尚未完成独立关闭对账。

## 源码完成与限制

当前consumer preview15及其全部05–15派生历史、32-module/17-material前置门、两域原件预算、legacy与active分离、三个module修订、native材料builder、纯四参数源码门草稿、数据表压缩和publication renderer均以明确source-only状态保存。尚未绑定最终Root3/bridge/发布器，不能据此运行新epoch。consumer八份当前源码额外以普通文件提供以便审查。源码压缩只用于无损归档保存，不能代替运行时源码大小或原件预算。

已知consumer候选联合账410个唯一正文共30,674,137字节，32MiB上限尚余2,880,295字节；这不是最终闭合账，也不证明两次新测试可容。物理副本域仍全部计费，正在收紧实际writer配额及删除仅由表示重复产生的成本。新nonce尚未授予。

## 如何核验归档

archive/ARCHIVE-MANIFEST.json固定每个连续分片的偏移、字节数和SHA256，以及重组XZ、解压TAR和完整SOURCE-INDEX的身份。SOURCE-INDEX同时以独立连续分片提供，也完整包含在TAR中；每个原文件保留全部字节及本地读取身份bookend记录。恢复工具先验证整个闭集再create-only解包，绝不执行归档源码。此本地归档不声称复现原远端文件系统元数据。

单表UNIX诊断的随后结果、final runtime后继、紧writer配额及整体验收继续追加下一检查点；不回写本快照的完成状态。
