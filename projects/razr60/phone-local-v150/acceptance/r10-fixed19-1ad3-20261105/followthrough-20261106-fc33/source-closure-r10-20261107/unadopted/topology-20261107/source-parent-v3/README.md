# 完整 source-parent reader：独立未采用候选 v3

## 已完成的交付

本增量把 v2 中尚未派生的完整 source-parent boundary reader 做成了独立的新身份候选，并对三个公开入口完成真实保全原件的端到端离线差分：`boundary_from_original`、`closed_boundary_originals`、`require_failed_ancestor_tail`。它没有修改 v1、v2、任何冻结源码或历史 receipt；没有运行 phone、ADB、native task、stage、CAS 或 reservation。

Mac job `1a1b8be2d97-12894-10d4` 在 `1794100900868` ms 完成，succeeded / exit 0；terminal publication、output complete、output durable 均为 true，没有 timeout、cancel 或 automatic retry。stdout 完整 63,930 B，SHA256 `7d39c5ad031a637175250d1cf5cdfe89c331acb0d042b922fb276536b6d260af`；stderr 0 B，两条流均已读到 EOF。全部 29 个实际来源文件在执行前后重新读取，其完整字节、SHA256 和九字段元数据一致。公开报告为 `reports/FULL-REPLAY-SAFE-v3.json`；原始 stdout、host 请求、精确读取清单和私有 fixtures 保留在本机，不导入仓库。

结果包含 12 个完整真实正例：10 份逐层原 boundary、final04 的完整 inventory / closure，以及由 final04 加九个旧失败祖先组成的完整 tail。final04 inventory 为 44 roots / 3,823 entries / 1,345,535 B，SHA256 `4bd70b72d2a92a6c963912159d9e978fc681a35ddb30c03a2c741700bf47cde4`。所有历史返回对象逐项相等，所有外部 callback descriptor、返回字节与顺序相等。

17 个完整反例覆盖原件截断、类型、路径、组合与 package、固定祖先 full9、tail 长度 / 次序 / 重复 / 原作用计数、prefix 的完整前驱身份，以及 retained 原件的首次读取和第二次 bookend 损坏；异常类型、文案和先后顺序均与旧实现一致。另有两项完整构造拒绝检查：声明的 constructor bytes 不等于实际加载 bytes，或原件 provider 不可调用。

保全数据中的旧 final04 `component_qualified:true`、两次 native calls 仍只属于旧身份。当前案例 credit 始终为 0。retained final02 的 `original_sender_wait:UNKNOWN_UNCHANGED` 完整保留；这个包不改写任何未知结果。

## 新执行代码与历史数据锚分开

| 对象 | 字节 | SHA256 |
|---|---:|---|
| 原 source-parent 源码 | 153,138 | `27350db238c5ca31796af91c77b5c2fdb9d02b838d35140f759df907903d4fa4` |
| 新派生完整 source-parent 源码 | 153,792 | `be12800aa1f8bec53a3c56545b5d8db17da864855e3c1d3e7d268451f544547d` |
| 构造器源码 | 19,589 | `8f1eeb66110127ee295d356b3f365ea209969c689c6a80bfdb0ad1520658fd42` |
| 构造器 bound loader | 1,023 | `845404b6ea78bd209c4cdf05d6c87453bda9ded4d46d6d42c6bd83757527a5ca` |
| 新 inventory 函数 | 3,827 | `0356d2bd56da36267a72bfb732125eb8807dc6ff32c47789ba8cbc1b523e7f51` |

`candidate/bound_loader.py` 先核对实际准备 compile 的 constructor bytes 的独立固定 pin，再要求声明的 `implementation_source` 与这同一份 bytes 完全相等。构造器内部再次核对实际绑定 bytes。这样 construction receipt 的实现身份不能指向任意无关字符串。

构造器先验证冻结原协议规定的全部 15 个依赖，再从精确旧 source-parent 字节产生新完整模块。每个替换要求唯一位置，反向替换必须恢复全部原字节。新的 module name、`__file__`、globals 和源 hash 都与旧模块分开；原外部模块的 globals 不被修改。

原 `reviewed_source_sha256()` 的九个非 attribute 调用按 AST 精确识别。历史 boundary、旧输出数据和历史 manifest 继续使用 `source_parent_historical_data_source_sha256()`；它校验原 source-parent 字节后只返回历史发布者数据锚。property 与 sidebranch 的当前 composing source 改用 `source_parent_execution_source_sha256()`，绑定真正执行的新完整字节。新的模块没有旧 `__reviewed_source_sha256__` 执行身份注入，也没有旧同名 getter。

property reader 的 `_PROPERTY_CURRENT_INVENTORY_PIN` 随实际新 helper 更新；嵌套的 property 和 sidebranch composition 使用各自新的 `UNADOPTED` schema。原有嵌套 reader 在 fresh module 中执行的 helper composition 机制保留，并在 provenance 中说明；这个包不声称历史嵌套模块从未进行其原本已定义的 globals composition。

新 reader 的 schema 是 `hepta.UNADOPTED.derived-source-parent-reader.v1`，并明确 `historical_reader_functions_changed:true`。返回值使用 `hepta.UNADOPTED.derived-source-parent-result.v1`，原返回对象放在 `historical_result`。该对象是历史证明的数据投影，不能被消费为“旧实现原样执行”的证明。新的 actual execution source、constructor、helper、15 个原来源和全部派生步骤由外层 `execution_provenance` 说明。

完整 source chain、函数图和可重复派生身份列在 `SOURCE-PARENT-CANDIDATE-MANIFEST-v3.json`。原模块保守静态闭包包含 55 个函数和 1 个类；新模块为 56 个函数和 1 个类。图包含所有模块内名称引用，因此是保守图，不声称等于一次运行的实际调用集合。嵌套 property / environment / policy reader、sidebranch verifier、retained-stage verifier 和原件 callback 的动态边在 manifest 中另列。

## 原内部接口与外层严格原件门

实际差分验证了一处必须保留的原接口语义：对于 source-parent 自己的当前前缀，旧内部 `boundary_from_original` 允许结构合法的 self descriptor，而冻结外层 `_source_parent_original` 才把它与显式 source-parent record 的路径和全部九字段元数据比较。

测试把当前 descriptor 的 inode 改为另一个合法整数时，旧 / 新内部 reader 都接受，完整返回数据相同；同一输入经冻结外层 `_source_parent_original` 则按原文案拒绝。这个兼容案例单列，未伪装成拒绝成功。固定祖先的 full9 被修改时，原 / 新内部 reader 均拒绝。未来生产选择器必须继续保留外层严格 record 绑定；本候选没有替换它。

## 性能的实际边界

Mac / Python 3.9.6，三轮交替顺序，无 profile / trace 的整个入口中位数如下。新入口的 envelope 与 provenance 返回开销包含在测量内。

| 完整入口 | 原实现 wall time | 派生实现 wall time | 原 / 新 |
|---|---:|---:|---:|
| boundary | 0.267111833 s | 0.243721792 s | 1.095970249× |
| inventory / closure | 1.911227875 s | 1.633234834 s | 1.170210086× |
| 全部祖先 tail | 2.060368959 s | 1.982367084 s | 1.039347846× |

29 份固定原件在计时前读成 immutable bytes。每次入口都重新运行完整验证和嵌套模块构造；retained callback 每次重新核对所给原字节，无 PASS、返回结果或 live observation 缓存。外部文件预载和顶层 reader 构造不计入这些入口的测量。

这组数字不能与 v1 的局部根谓词、v1 scope 或 v2 R9→R8→R7 组合的倍率相乘，不能当作整条 `verify_retired` 或实际手机 stage 的耗时。新增代码解决的是完整 reader 的显式新身份构造缺口，也取得上述有限的局部完整入口改善；整段 90 秒门尚未实测通过。

## I/O 与预算的边界

完整测试使用原接口已有的 `__reviewed_package_sources__` 和 `__retained_stage_read_pinned__`：前者提供全部 byte-pinned immutable 来源，后者提供旧 final02 要求的精确 old39 inventory。没有 stub `C.read`、`C.pinned`、`Path.stat`、`Path.lstat`，没有改旧原件的 hash 或元数据，也没有以一个旧 PASS 代替本次验证。

独立的一轮 profiled 新 closure + tail 观察中，历史 `C.read` / `C.pinned` / `original` / `describe` 调用为 0。Mac 的原模块装载路径仍触发了 16 次 stdlib `readlink`；同一 Linux 诊断观察到 `lstat` / `stat`。这些 metadata 调用来自继承的模块路径处理。该诊断不覆盖 preload、顶层构造或任意完整系统调用，并且完全排除在三轮计时之外。

因此这里的“完整”只修饰三个 historical reader 入口及其实际验证结果。生产的 archive validation、Common 文件读取、stdlib metadata 读取、实际依赖读回、live inventory 与所有预算消耗仍须在真实生产执行图中逐笔计量。离线 immutable 预载不构成生产计量豁免；任何生产 `UNMETERED_READ` 不能用本包 PASS 解除。原 stage transport 90 秒、业务 turn 300 秒和原 lease 创建 / 加载约束均未变。

构造器 receipt 明确把 input provider 视为外部 callback，未自行证明该 callback 的实现来源或 fresh phone read。未来生产适配必须绑定该 provider 的来源、实际读回和预算。它也必须保留未知状态、旧请求不可重放及原组 / 锁 / cancellation guards。

## 可移植验证与采用仍缺什么

从承载 v1/v2 的 `topology-20261107` 目录运行：

```sh
HEPTA_TOPOLOGY_SYNTHETIC_ONLY=1 python3 -B source-parent-v3/tests/test_source_parent_candidate.py --base .
python3 -B source-parent-v3/tools/build_manifest.py --base .
```

portable 为 14 tests，明确跳过两个私有 fixture tests；788 个完整 inventory outcome 对照、1,754 个路径拓扑对照、10 项实际 source / 声明 binding 拒绝、3 项 constructor 依赖拒绝、2 个 envelope unit cases。新的完整模块 helper 在原 property reader 的 13 项受限 builtins 下执行这些对照。`--report` / `--output` 只能创建新路径，默认输出 stdout；CI 可在临时副本中运行，不覆盖保存的原报告。

仍需生产工作：把当前 `source_parent_reader()` 的 exact-old contract 改为正式审阅并冻结的新实现选择器，明确检查新 construction/result schema 和实际源链，再显式取 `historical_result` 给原历史数据验证流程。不能继续沿用旧 `historical_reader_functions_changed:false`，不能把旧源 hash 指向新代码，也不能省略 `_source_parent_original`、exact closure 与 tail 等外层 guards。

此外，完整 current `verify_retired`、所有真实 I/O 与 stage 90 秒预算、R10 失败的正式结算与保全、精确新采用 tuple、head/base checks、独立 review、fresh input / preview / CAS / single reservation 都仍有各自门槛。这个候选不接管生产入口，不授权新 nonce。当前 fixed19 19 项、BUILD / 安装 / READY / 新 nonce health / 真实业务 / 独立回滚以及日常与显示支持范围，继续沿 v1/v2 的逐项状态和原协议，不获得本包带来的运行资格。
