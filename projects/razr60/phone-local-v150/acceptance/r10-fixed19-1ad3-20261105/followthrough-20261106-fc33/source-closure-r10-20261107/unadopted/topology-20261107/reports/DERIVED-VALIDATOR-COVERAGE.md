# 派生验证器覆盖与采用边界

## 已实现并验证

| 消费点 | 原源身份 | 原函数 → 派生函数 | 已验证范围 |
|---|---|---|---|
| 当前 `late_boundary.inventory_value` | 259,866 B / `f9a19df8a2a1d8b6a09a8c75eec118f4304ad1db5f40fc005fd7d59fb02837b7` | 3,788 B / `086dedcdc7ac8d1627e1c2592ed7a9f130a4395dd4b27e9bc86a512c91af06f1` → 3,827 B / `0356d2bd56da36267a72bfb732125eb8807dc6ff32c47789ba8cbc1b523e7f51` | 完整函数 801 次接受/拒绝/错误/返回差分，另 1,754 次拓扑对照 |
| source-parent `inventory_value` | 153,138 B / `27350db238c5ca31796af91c77b5c2fdb9d02b838d35140f759df907903d4fa4` | 原/新函数字节与上一行分别相同，完整源身份不同 | 独立绑定此原源再跑 801 次完整函数和 1,754 次拓扑对照 |
| retained R8 scope `verify_complete_scope` | 21,865 B / `937a34f4ba752e14bb78b1566c672e89b2e26502392d8d2a3561a52ceb88af38` | 8,083 B / `798ffcd349da388ba6985b0b5e9a34beb436656aed300d3980280cea100d64a6` → 8,369 B / `51bd57dffe1a2beca21a3d01288477030f61988daa3d294fdf8d371ade6c9f89` | 完整原 capture 返回全等，6 个完整函数拒绝/优先级 case，291 个纯拓扑子图对照 |

`tools/build_candidate.py` 和 `tools/build_derived_fragments.py` 校验完整原源 hash，只替换唯一已声明区块，并做 whole-byte inverse。候选函数没有入口、phone 调用或自动采用行为。它们不改变历史文件，也不把新代码的身份写成原 reader 身份。所有 root sets、depth sets 都在每次函数调用内新建；没有缓存 PASS、live observation 或完整 validation result。

## 为什么前缀判定等价

对于已通过原绝对、canonical、无 `..` 校验的同一 POSIX Path flavour，严格祖先关系等价于 `a.parts` 是 `b.parts` 的严格前缀。`/` 和 `//` 是不同的第一个 tuple 元素，不能被字符串 strip/normalize 合并。等深不同根不会互相成为祖先；相同根由原更早的去重 guard 拒绝。旧 predicate 的 equality exception 保留在严格前缀条件中。

R8 scope 的插入点在原 capture/source/old-inventory pins、前后完整 inventory、roots/cardinality 和旧 entries 内容检查之后。旧根属于已独立验证的固定 R7 inventory；因此这里使用按 Path.parts 建立的集合不会提前接受坏根。其 `any(Path(path)==Path(root) or Path(root) in Path(path).parents ...)` 等价于检查 entry parts 的非严格前缀。对每个 `after['entries']` 的遍历顺序和原 `need(..., 'no new child added below any old retained root')` 调用顺序均保持。

复杂度表述：移除了逐 root pair 构造 parents，以及逐 entry×root 重复构造 Path 的工作。只枚举实际根深度，并不无条件等于线性时间；tuple 切片和 hash 仍有成本。按每条路径深度 d 保守上界可到 `O(sum d²)`。报告使用实际完整函数测量，不用局部 predicate 的倍率估算 stage。

## 实测与边界

Linux 本地当前 `inventory_value` 在真实 R9 after（49 roots、3,991 entries）上，7 轮无 profile 中位数约 **147.405 ms → 63.908 ms，2.307×**。纯 root predicate 约 76.929 ms → 0.026349 ms 只是子表达式测量。

Mac 原保全 archive 重建完整 R8 scope（before/after 各 3,991 entries、旧 47 roots / 3,918 entries）后，两个实现均使用同一个未改 original `inventory_reader`。3 轮无 profile 中位数为 **0.983765750 s → 0.254996375 s，3.85796×**。整个 scope 输出与原 receipt 全等；原 unknown/null、预算、过期 lease、zero-credit 语义均保留。原 job `1a1b85e2021-12894-ec5` 为 exit0，完整 stdout 7,790 B、stderr 0、两个 EOF；原输出及 authoritative status 存在 `reports/scope-full-mac-results.json` 和 `reports/scope-full-mac-execution.json`。

上述是不同机器、Python 版本与不同函数边界的测量，不能互相直接比较或相乘。没有运行新 stage、没有证明整个 90 秒预算已通过。

## 完整组合必须覆盖的调用点

| 必须明确的新 selector 路径 | 固定历史来源 | 必须保留的检查与身份边界 |
|---|---|---|
| 当前 late-boundary 的 `inventory_value` | 当前 R10 源 `f9a19df8…` | 新当前源自己取得新的 package/source/root 身份；不能就地改冻结 R10 |
| `source_parent_reader()` 选择 source-parent reader | `reference/source_parent_late_boundary_r4.py`，`27350db2…` | 原 reference bytes 和旧 publisher/boundary 保留；新 derived reader 使用自己 module/source 身份；不能保留错误的“执行代码仍是旧 reader”声明 |
| 当前 direct retained R8 → `verify_retained_staged_archive` → `verify_payloads` → `load_module('scope')` | R8 reader 96,088 B / `614f44d6eb75f47b02e32b463f18534e2d0bc5a3e8fd928535e7da17909679ae`；内嵌 scope `937a34f4…` | 先 decode 并核验旧 scope 的原 pin，再由新的明确 constructor 派生新 module；原 capture/lease/limits/closure semantics 不改 |
| R9 → `verify_retained_transport_archive` → 原 R8 dependency | R9 reader 34,650 B / `919d508899f405a5942766ad5d9adf0bfa0600aa0bc2e51552a835b5a8c7fbd3` | 必须覆盖嵌套 R8 路径，否则本次实测热点仍保留；先核验 `read_exact(R8_READER)` 原字节，再显式选择新 derived R8 实现 |
| R8 `verify_payloads` 提取 actual `inventory_value` | 实际 old library late 源 218,894 B / `9adcd6a865875f209bf56cfadc952b40cf4984889cb3450837446b6b95dcbd54`；函数 `086dedcd…` | 验证 original source/function pin 后再编译新函数，记录两种 identity；不能继续称新函数是 unchanged original reader |
| R9 `verify_failed_r9_scope` 的 old/before/after inventory reader | R9 scope module 37,788 B / `f59bae34d9acc80d2c28cd5636b53e13b68d911d2121735883dc7b001e57779f`；相同 actual old library late | 与上一行同理；新调用路径保留完整 byte/readset/role/terminal/unknown 验证 |
| 更早 property/environment/non-native reader 家族 | 冻结 `SOURCE_PARENT_READER_DEPENDENCIES` 的逐项原件 | 仍需 selector 的完整 transitive map；本次 fragment PASS 不覆盖未明确派生的旧 reader 或整条新准入链 |

R7 reader 37,404 B / `5935f4d4b3f00d914c6e0f9aec4429cf424a0601685061fe9277de3df5403b21` 本体未发现直接 Path.parents loop，但它会提取旧纯 inventory reader；不能据此把整个 transitive family 宣称已优化。

## 生产采用仍为 HOLD 的具体原因

当前 `source_parent_reader()` 的原 provenance 明示 `historical_reader_functions_changed:false`、`historical_publisher_identity_changed:false`、`validation_result_cache:false`、`current_tuple_credit:false`，并核对旧函数的 `__globals__` 和 old-source overlay。选择一个新 derived implementation 后，不能把同一个旧 reader provenance 直接套到新代码上。应把旧来源 bytes、历史 publisher 数据、新 validator implementation、constructor 和本次调用 receipt 分开绑定；`validation_result_cache` 与 `current_tuple_credit` 仍保持 false。

R8/R9 loader 也把具体 source bytes/pin 与原纯模块绑定。离线组合可在核验这些旧来源之后执行独立的新 module，但生产 release policy 必须明确接受该新验证来源。所需采用决定、source closure、review、exact head/base checks、新 freeze、R10 failure 保全与新 fresh admission 均不由本包的离线 PASS 自动产生。原 budget、进程组门、锁门、前后 inventory/readback、CAS、reservation 和一次性身份都不能被优化省略。
