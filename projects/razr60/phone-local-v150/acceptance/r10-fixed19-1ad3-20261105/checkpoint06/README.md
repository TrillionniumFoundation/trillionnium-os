# Checkpoint06 — 当前证据封存，整项仍为 0/19

本检查点封存独立复核通过的 CP06 draft02 的761份原字节，并增加本说明、独立审查报告和检查点清单。父提交为 `dd299611fc2044fb87d3ee8c76fcaa361108774d`，父 tree 为 `a1a9b7fd5160c11616fc0b08a90eae2b1315e68f`。全部路径新增于 `checkpoint06/`，既有 CP03、CP04、CP05 原件保持。

## 资格状态

全量19项业务/组件/负向验收当前仍为 **0/19**。既有 **host 层5/5** 与 **policy post comparison16/16** 分开记录，不折算为物理用例 PASS。源码准备、只读采证、归档下载及失败收尾也不增加整项资格。主任务继续，后续进展通过新检查点保留，原历史记录不回写。

Mac 已用固定 e78d verifier 对 e85b failed-prelaunch admission 的119份实际原件完成只读重算；它只覆盖 external09 与1ad3-01。其原父进程未 JOINED / 未 EOF 的历史保持，不覆盖最新1ad3-02或external902。

## 已取得的真实证据

- `root-r10-neg01-1ad3-02` 在 phone-stage 完整累计库存相等门终态失败。完整 Mac109文件、15目录、6,126,794字节原件归档及全部成员SHA已验证；七个已执行host阶段原JOINED/EOF回执保留。内部phone rc1与包装层rc0分开记录，失败不变成PASS。
- 后续只读inventory观察增加76项、删除0项、两个目录条目变化，旧文件内容未变。external902/`root-r10-neg01-7c907661-01`记录时间早于该Root尝试；后观察不构成失败瞬间原子快照或执行者归因。
- external902的exact76范围中72文件原件、private118、snapshot因既有capture01而create-only拒绝的原件、existing-capture只读观察分别以完整12成员原始归档保存。CAPTURE272、capture RESULT和boundary9686三个完整body另保留。其runtime31da/Rootf865与本Root的a334源身份分开。
- 原Mac sender54589仍为NOT_JOINED、stdout/stderr EOFfalse。后来sender结果、恢复记录、P4或进程观察不能改写原父进程证明。
- Source-stage15/16/17、实际a334源码cascade、seal-interface、各固定观察器/caller、Mac/P4collector、独审均按各自实际范围保存。各source manifest的原历史state保持；实际执行回执另存。

## 明确的未完成范围

| 范围 | 本检查点实际取得 | 保留的缺口 |
|---|---|---|
| external902 P4归档 | 原manifest完整，230个完整成员逐件对原pin；sender116、setup55、material56、setup计划3 | 原820660字节XZ尚未完整，另5个sibling成员未纳入完成；不宣称235成员或whole-XZ校验 |
| external902 Mac归档 | 30/35个原始版本范围，原controller完成记录 | 缺XZ一段及manifest四段；不宣称本地完整239成员 |
| phone capture原归档 | CAPTURE272、RESULT、boundary的完整body及原归档descriptor | 原2204770/462da4归档body尚未取得；缓存复用不冒充取得归档 |
| published closure/独立host重算 | 已得descriptor和既有观察范围 | 活动中的closure下载、未冻结9f4 host-audit候选排除；关闭结果仍待独立验证 |

P4首个持久只读operation仅取得SDK payload的53,248/87,827字节，随后四个已经在途的结果页超时。全部原错误、版本、分页与部分状态保留。远端collector完成不等于本地传输完成；以后补齐不能抹掉这些失败。

## Codec增量与来源边界

codec `8f60` 仅在原失败分支透出POSIX命令替换后的值，并追加诊断记录；它不是Java原始字节流。三个实际host检查、原gate图和更正gate02一起保留。成功路径、guard与预算未改；该候选未部署到生产，不代表已获得设备上codec失败的因果证明。固定三个boundary叶reader与help-only caller按源码准备状态收录，不由源包存在推断实际运行。

## 可复核保存方式

声明的source manifest成员集和每份SHA保持。原始归档逐成员核字节；重复的native JSON/base64回执可通过明确标注的本地无损载体还原。P4的230成员载体是从不完整原XZ前缀得到、逐件命中原manifest的本地派生包，不能称原远端完整归档。无损载体不声称复现原文件系统元数据，full9来源保留在原观察和manifest中。

`CHECKPOINT-MANIFEST.json` 列出其余763份文件的字节、SHA256、Git blob身份及来源，包括完整继承761集和新增的两份说明/独审。它自身通过外部发布索引和Git tree绑定。Git对象上传与tree验证不会改变任何用例资格；最终分支发布由Root执行期望HEAD的CAS。
