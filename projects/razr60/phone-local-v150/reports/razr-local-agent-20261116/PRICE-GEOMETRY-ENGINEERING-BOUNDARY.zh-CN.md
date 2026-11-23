# e999 自然价格：推荐区原生几何拒绝的工程判断

复核日期：2026-11-16。仅分析已经保存的手机证据；没有手机操作、重跑测试或修改源码。原任务仍为失败。

## 实际失败发生在哪里

自然价格 case `natural-price-e999-01/run-12ebafcc` 的观察耗时 37.881 秒；资格检查先为 false（1.329 秒），下一轮为 true（2.731 秒），随后完整原生括号检查在 4.611 秒后抛出 `visible native recommendation escaped its container`。此时本轮有界重试还剩 6.797 秒；不是本次 RPC deadline exhaustion。模型进程没有启动，步骤数为 0。清理、路由及主屏保持验证通过。

原 `compareNative` 的合并谓词是 `contains(recBox,rowRect) && !overlap(targetBox,rowRect)`。它在完整原生快照的可见推荐子节点上执行。错误没有记录首个失败 path、前后 canonical row SHA 或失败的是哪一个合取项。新增结构诊断只为原有 `WebNativeObservationChanged` 类型附加数据；本例是另一条原有通用异常，故没有 `native_change_structure`，不能说新增诊断已经证明该行无害。

## 保存帧能证明的几何

第二轮两帧完整文件 SHA 分别为：

- before：`e1fa4508e8de24a72b42e783451511da0527c8b3c48a0d207842b07328de27ae`
- after：`60b0fcc404eb536721b21f4d3d49642111cc8706749c01cf4b6f133eeb0f1944`

两帧各遍历 559 个节点，保存了 388 / 392 个 retained 节点。没有因遍历/文本/节点上限而产生的已报告遗漏，但 retained 行本来就不是完整 private native snapshot。

| 对象 | 原生路径 | 矩形 |
|---|---|---|
| 唯一搜索卡候选 | `0/2/0/0/0/3/4/1/0` | [0,494,292,918] |
| 推荐区 | `0/2/0/0/0/3/6` | [0,1101,1210,1397] |
| 推荐区外 clickable 兄弟 | `0/2/0/0/0/3/7` | [0,1397,1210,1445] |
| 一个推荐 clickable 子节点 | before `…/3/6/0/5/1/0`；after `…/3/6/0/0/1/0` | [55,1411,175,1441] |

保存的推荐子节点共有 40 / 44 个，其中 15 / 19 个不被推荐区矩形包含。所列超出节点与目标卡没有正面积交集。然而表中的推荐 clickable 子节点与推荐区外 clickable 兄弟存在正面积交集。不能宣称超出部分全是空白、没有其他控制区域或没有遮挡。

共同祖先 path 是 `0/2/0/0/0/3`，但该行及数个中间祖先没有被 retained 序列化。已保存 WebView 祖先矩形为 [0,145,1224,2992]。after 另有 [1224,1101,1225,1377] 的一像素宽 retained 节点，不能凭它在屏幕边界外就将真实 private visible 标志归零。具体结构、哈希和观测边界见同目录 JSON。所有 retained NodeRef hash 都不替代原私有 canonical row SHA。

## contains 是否可能拒绝合法布局

**可能，但当前证据不足以把本次拒绝认定为误报。** Android 的 `getBoundsInScreen` 文档承诺屏幕坐标；它还明确 accessibility parent 与源 viewParent 不一定相同，并没有承诺每个 AX child 的矩形都必须被 AX parent 包含。CSS 标准允许 `overflow:visible` 内容在父盒之外绘制。这说明 parent-contains-child 不是通用框架不变量；目前 contains 是 Hepta 额外的保守范围策略。

该结论不证明本页的实际 overflow、clip、transform、z-order、命中或事件路由。特别是已存在另一 clickable 区域的几何交集，不能用一般 CSS 规则把本案所有变化归类为无害轮播。

主源：[Android AccessibilityNodeInfo](https://developer.android.com/reference/android/view/accessibility/AccessibilityNodeInfo)；[W3C CSS Overflow 3](https://www.w3.org/TR/css-overflow-3/#overflow-properties)。访问日期均为 2026-11-16。

## 最小可审设计边界，尚未实现

若后续产品确实需要允许“推荐内容超出推荐父盒，但完整观察仍证明当前目标卡”的情况，应明确新增 **price-only 原始目的绑定的只读目标隔离证明**，不能在共享 comparator 全局删除 contains：

1. 输入必须是服务当前拥有的完整前后 private snapshots、原 task/lease/window/epoch/capture 绑定以及完整 DOM card 证据；证明固定前后 canonical SHA、目标 path、推荐 path。retained 节点不能生成此证明。
2. 仍完整验证 membership、目标角色、稳定推荐根、同一 WebView、全部非推荐原生字段严格相同；推荐内只允许原有字段集合变化，并继续拒绝 editable/password/focused/scrollable 等状态。
3. 必须遍历全部可见推荐前后矩形和全部原有 foreign rows，验证真实目标卡无交集；不将矩形裁到父盒、丢弃越界节点、归零 visibility 或跳过成员。增加的结果只陈述这些实际检查，不声称整页无覆盖。
4. 若选择继续要求不碰其他控件，还必须基于完整快照及真实祖先分类对外区控件逐一检查；本案已保存 n18 交集必须拒绝或保持明确未知。现有数据不足以批准该交集的例外。
5. 此对象不可成为 action Permit、ARM、完成证明或跨目的 boolean。服务 live recheck、真实 target/window/signature/authorization 保留。

上述设计仍缺少本次首个失败私有行、完整祖先/控件集合和 native↔DOM 的 clipping/hit-test 关系。本案的已保存子集不足以离线认证新策略通过；也不能声称该设计会使本案成功。

## 只改入口为什么不会完成任务

原代码在多个更晚阶段继续调用严格比较：

| 阶段 | 现有严格调用 | 仅放行初始只读入口的影响 |
|---|---|---|
| 服务返回前 live graph | `HeptaAccessibilityService` 中 `compareNative(observedNative,liveNative,targetPath)` | 越界节点仍可能立即拒绝 |
| 初次建立搜索卡报价 | `WebShoppingQuote` 构造 `compareNative(rows,live.after,targetPath)` | 甚至可能还未发布给模型就再次拒绝 |
| model done 前新鲜捕获 | `supportsCaptures` 的 STRICT 路径 | 原严格 DOM 资格仍需通过 |
| accepted done 后最终读取 | `Pending.complete → compareObservationBracket` | 完整严格 native/DOM 括号仍需通过 |
| 真实动作 | 原 target/window/signature、ARM 与授权检查 | 本次观察证明不赋予任何动作能力 |

`WebShoppingQuote.java` SHA 是 `af4791997c7920c74b3192c1d091aaffaef1fbf2446521b72bede4f80a1cb776`；`WebShoppingObservationStability.java` SHA 是 `1e20cc8428b11f91b1a78b7645728f0311b09275139e40c5399f091be0450ccb`。这些相关方法在本轮冻结版本中未变。

所以“只读观察可发布”和“用户收到独立核验的价格完成结果”是两个工程范围。若后者也要采用新的目标隔离策略，必须另行设计和审查 private quote/completion 的显式同目的重放，不能借修改一个共享 helper 暗中扩展。当前没有这样的修改。
