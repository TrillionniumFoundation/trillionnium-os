# Checkpoint07 — 新的完整原件与源码检查，整项仍为0/19

本检查点追加于 d51ced3df77635ef5f88680a2fad9d495443b5a3，不改写以前的检查点或失败。完整19项验收仍为 **0/19**；已完成的 host NEG04/05/07/08/09 **5/5** 与 policy post comparison **16/16** 独立列账。

## 新完成的实际证据

- Root02 fixed prelaunch admission已在真实Mac重算32份原件。实际proof为26,459字节、SHA256 09af0bd18020aaf31432187aa0f24ddec5cba8227b64a859e68294eeab94a10d，与预期整字节一致。源/证据先完整准入再create-only落39文件。控制进程、原stdout/stderr和终态均完整。首次whole-archive write超时的unknown仍保留，后续固定upload_id的expected-absent提交不把它改写成成功。
- external902已用实际原源码完成独立host closure重算；49项closure字段、137份实际host full9、160次guarded reads均有完整原件。旧sender54589的NOT_JOINED、双EOFfalse不被后续结果升级。
- current-head只读观察完整保留实际902头、27根/2623项/19,424,531字节、原角色与endpoint观察及双端原件。它不是未来输入许可，也不延长旧lease。
- kernel query02完整收尾，仅能证明固定窗口没有保留下来的匹配AVC；可用性和codec72原因仍未知。没有再截图或重放原action。
- retained-footprint read01因512KiB元数据上限拒绝，原phone rc1和缺少原phase的限制完整保存。read02仅修正父目录重复表示并保留失败phase/counts，读门与所有预算不变；本次controller/actor/phone均0，完整durable终态、双EOF、70固定版本分块和12成员XZ全部核验。
- read02实际得到146现存对象、126完整文件正文（7,114,062字节）、65正面ENOENT、22完整父目录表、34祖先、130个可精确展开引用。物理双读252次/14,322,260字节，完整元数据301,485字节，观察用时约1.53秒。Root独立重算所有分块与正文；metadata projection明确是派生件，完整原正文仍在原归档。
- 原external902 P4归档已用逐件匹配原manifest的既存精确字节无损重建，完整820,660字节SHA ab778aa6…；原SDK分页和早期下载不完整的历史保持。

## 源码工作及其边界

固定失败三身份的inventory v2源包已冻结并独审，固定7 legacy+最多8 active的潜在fixture界、64 roots/30000 entries/512MiB/30s不变，三失败nonce永久不可复用。源中extra binding仍为None，不能据此启动runtime。

consumer已加入显式phone/mac/p4 context、非阻塞regular-file读取和32MiB完整原payload池门。shared17与明确COMBINATION现在在首次runtime exec前读取；同长度篡改、缺件、重复件、旧manifest和错误combo均拒。preview03错误沿用旧121416清单被真实byte检查拦下；preview04绑定正确af0d清单。10必要局部门通过，final epoch capsule、两域语义和完整cascade仍未接完，所有预览明确非runtime-ready。

historical inverse仅用已审15段字节范围与192 literal bytes恢复原c50/67dc，缩小纯校验capsule；不执行旧main，不授予用例资格，不改变原失败。

## 本检查点仍未完成

1. 完整有界epoch协议、Root3/bridge、snapshot/closer、consumer两域接线与最终源封存尚在进行。
2. active prestage的executor父目录不存在问题已发现。后继方案采用完整Android caseparent，并对GNU/Android全树别名双读双计；本检查点不把未冻结后继当最终可运行源。
3. 三roles六日志的写入上限、截图PNG专用子进程写界、client回执/trace组合上界与全部复制域资源账尚待完成。
4. fresh case-home父names还含root-r10-neg01-20261104-02和root-r10-neg01-7c907661-diag01；来源、范围及关闭证据正在对账，不能根据名字默认已关闭或免计资源。
5. NEG01/NEG02新资格、最终sealed release及其余业务/物理/NEG06/NEG10–14验收仍未完成。没有新case nonce/lease或epoch初始化。

`CHECKPOINT-MANIFEST.json`列出每份新增文件、SHA256、Git blob身份和来源。下载原工具回执另用明确的本地无损载体保存，非新的远端采集；不声称载体复现原文件系统元数据。Root02共享transport历史/配置没有混入交付。后续进展继续追加新检查点，不回写此时状态。
