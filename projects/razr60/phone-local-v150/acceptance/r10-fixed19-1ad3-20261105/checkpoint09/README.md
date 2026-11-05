# Checkpoint09 — 完整现场观测与主机审计失败原件

本次只追加在 cd156bebb6b883497877f17821738d0a9bf3e774 之后。用户指定的 E2E01–04、COMP01、NEG01–14 共19整项仍为 **0/19**。已有 host NEG04/05/07/08/09 的5/5及 policy post-comparison 的16/16分别保留，不能升级为手机物理或业务通过。

## 实际完成

完整fullfrontier第二次观测在真实手机执行一次，controller/actor/phone均返回0，实际原件完整取回。10个原生固定版本分块重组607156字节归档（c094d0c7…），单个XZ包含12份原件。两轮均有942个PID，1884份stat正文和6份网络表逐份解析；三个历史角色及对应PGID均未出现，目标端口与抽象socket均无匹配行。116份静态文件执行232次完整读取，两个运行目录别名都计费。实际4,110,286字节、3038操作和8.88秒在原上限内，已独立重算。所有8个net元数据操作数保留；两轮unix named mtime/ctime各变化12ms，held/parent全9与named身份7相等。没有宣称全9始终相等、连续缺席、全局clearance、新nonce资格或未来输入许可。完整证据207原件加MF共208文件、17,592,549字节。Root及子任务各自的局部分析harness错误亦保留。

之前单表unix诊断及505首次fullfrontier失败原件继续保留，旧失败未升级。6077历史分支137 host body已全量取得；其深层历史真实host验证尚待执行，不能按本地缓存认定host full9或闭合成功。

## 主机审计

首次source staging在mkdir前被父目录名称大小门拒绝。独立只读测量得到1568个名称、79033字节pretty JSON，随后采用完整可逆prefix数据表示，保留4096数量和65536字段上限，展开字节计入原预算。修正版stage02实际成功，三个固定source文件经独立native完整读回、SHA和version核对；真实两轮名称为1577→1578且仅增加预定source目录。早先测量与stage之间存在其他目录变化，全部保留，不冒连续稳定。

owned audit01真实启动了原审计器，pid/pgid/sid=68061，returncode=1，双EOF及worker join完整。审计器写出了INTENT.json后在自有输出目录检查处失败：new-owned-output / owned output directory changed / physical read 60466。尚未调用完整历史verify_adoption。已保留实际controller、内层6原件、stderr与存在的INTENT；没有修改旧输出、重新分派或绑定成功authority。Mac目录元数据最小诊断与修正属于后继工作。

## 已封存的源码状态

consumer preview16–22、完整源码gate及其普通空白格式调整、主机audit/caller01–02、24-role profile草稿、publication actor/SDK、action gate06–08、桥接代码和紧writer配额都以source-only状态保存。preview22 release为122789字节（17536300…），纯四输入源码门已装入release/cascade/interface，但最终recipe/Root source authority仍为None。现有5项其他consumer脚本未改。任何源码草稿、局部检查或预算下界均不计作实际新案例通过。

归档及SOURCE-INDEX保留所选文件的全部字节。恢复工具先逐项校验再create-only恢复，不执行任何归档源码。压缩仅用于保存，不替代运行时源代码或原件预算。后续诊断/修正版审计、6077真实host复核、最终32模块、发布执行及19项验收继续追加，不回写本检查点。
