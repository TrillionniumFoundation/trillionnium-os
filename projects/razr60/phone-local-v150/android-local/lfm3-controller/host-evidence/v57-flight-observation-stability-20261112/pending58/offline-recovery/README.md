# Main58 离线恢复材料

当前手机实际安装的是 **Main57**。Flight57 已执行，但业务失败：5 个步骤、查询未派发、结果未就绪。采集器退出 0 仅说明采集流程完成。Notes 正常保存与重开、主屏滚动、取消及恢复的已验证范围仍属于 Main56。

## 实际阻塞

Main58 Core 只有一次真实启动确认，PID `3934790`、原会话 `dpty-2b06b0a65c7104136c17ada20448725cd25c353d94b590495d7de8214a34feb5`。最终退出码和 RESULT 尚未取得。主机连接先返回 `tunnel_client_not_connected`，后返回 `tunnel_client_not_seen`；两个原始记录均保留。

恢复连接后，首先读取这一个原会话或其已有 RESULT。**不要重新提交 Core Start。** 连接错误和未知终态均没有被记作测试失败或测试通过。

## 已保存的待恢复材料

| 环节 | 保存内容 | 当前状态 |
| --- | --- | --- |
| Core58 | 原启动确认、已提交源码和请求位于前一证据批次；本批保存第二次连接错误与 Root 离线审查 | 已启动，终态未知 |
| Focused39 | 正确的 `sha256` 两处消费修正、完整源码与请求已在前一批次；Root 离线复核记录在本批 | 未提交；旧请求未执行 |
| Web58 | 完整协调器、外置 fixture packet、必要测试增量、独立源码审查；确切请求已在前一批次 | 未提交；预期计数不代表通过 |
| Android58 | 完整输入、协调器、发布器、loader、supervisor、确切待封请求及 handoff | `focused_result=None`；**不得提交此未封请求** |
| 元数据与签名 | 完整源码和可逆变更 handoff | 8 / 10 个实际前件仍未绑定；没有提交请求 |
| 安装 | 完整源码、13 处变更、当前 Flight57 消费接口复核 | 13 个 release 字段和 OWNER 未绑定；没有安装动作 |
| Flight58 | 三份 runtime、RELEASE、PREP、RUN、三个发布器和纯主机发布请求 | 全部未执行；身份、视觉审查、坐标及未来 owner 未伪填 |

本批保存 **35 个已有原件实体**，另有本说明和精确索引。源码、请求和完整输入均直接作为 Git tree 成员保存；不是仅在 JSON 中引用未挂接的 blob。Android 原件的 Git SHA `0000c0684a9576e63aa63639385b1f2cdcaee3e0` 的前导零属于真实 SHA。

## 保持的边界

生产仍是 `313685edc580a750aea6301d8ff3cfd617d6fab6` 对应的 595 份文件。Main58 两文件候选只保存在证据目录，未替换生产树；Main57 原 PUB、MAP、全部历史失败和上一批 118 份证据原字节保持。没有生成 Main58 的成功 PUB/MAP，没有签名或安装 Main58，没有 Owner25，也没有重放手机任务。

本次归档没有主机命令、手机动作、新测试套件或生产修改。35 MB 历史 envelope 未在此解包；前一批保留的是已经重组全哈希验证的 gzip 和逐片原件，相关验证边界没有升级。

## 恢复顺序

1. 读取原 Core58 会话 / RESULT，先确定真实终态。
2. 确认物化源码符合固定输入后，由 Root 依原请求顺序执行尚未提交的 Web / corrected Focused。
3. 取得真实 Focused 成功结果后，封 Android 的最后一个实际值，重新生成完整源码和运输 pins，再执行。
4. 取得全部实际门和 Android 回执后，执行独立的 Main58 source CAS；随后封元数据、签名、安装及 Flight 前件。
5. 后续结果 provider 只能依据真实查询后 DOM / AX 实现，当前仍为 false。

精确成员、完整大小与 SHA256 见 [INDEX.json](INDEX.json)。Root 的新增离线审查和第二次连接错误见 [原始记录](ROOT-OFFLINE-REVIEW-AND-SECOND-HEALTH.json)。未绑定字段及各阶段的所有权见 [BG 清单](BG-PENDING-MEMBER-MANIFEST.json) 和 [Audit 清单](AUDIT-PENDING-MEMBER-MANIFEST.json)。
