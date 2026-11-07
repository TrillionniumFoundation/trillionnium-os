# R6 当前源码主机负例：原运行对账与独立核验

结论：NEG04、NEG05、NEG06、NEG07、NEG08、NEG09 六项主机隔离层均有完整的既有成功原件。此次工作没有重跑测试，没有派发手机任务、创建新验收 nonce 或修改生产源码。准备目录的旧 PREPARATION 记录落后于现场；本报告读取并保存实际原运行。

## 原运行

| 范围 | 原 job | 终态 | 原 stdout / stderr |
| --- | --- | --- | --- |
| NEG04/05/07/08/09 | `1a1b3383b35-fc05-8128` | exit 0，完整持久输出，无超时 | 3,481 / 0 bytes |
| NEG06 | `1a1b33784d4-fc05-8120` | exit 0，完整持久输出，无超时 | 554 / 0 bytes |
| 五项原件只读复核 | `1a1b3439b2e-fc05-8190` | exit 0，未再次执行 case | 4,023 / 0 bytes |

两组原 namespace 子进程均退出 0，原 direct wait 已返回，内核进程组 census 为无成员、ESRCH。五项使用的原 capture 同时保留 stdout/stderr EOF、reader join、原期限和创建时 inode 核对。

## 六项结果

| 项目 | 层 | 原检查数 | 本地测试副作用 | 用例耗时 | FD / 线程 |
| --- | --- | ---: | ---: | ---: | --- |
| NEG04：派发前断连 | host_isolated | 26 | 0 | 0.932 s | 5→5 / 1→1 |
| NEG05：作用后、结果前断连 | host_isolated | 34 | 1 | 1.608 s | 5→5 / 1→1 |
| NEG06：模型请求超时 | host_isolated | 22 | 0 | 1.858 s | 5→5 / 1→1 |
| NEG07：结果期限与迟到原件 | host_isolated | 35 | 1 | 2.280 s | 5→5 / 1→1 |
| NEG08：作用前取消 | host_isolated | 26 | 0 | 0.907 s | 5→5 / 1→1 |
| NEG09：作用后取消 | host_isolated | 33 | 1 | 0.979 s | 5→5 / 1→1 |

这些副作用是测试独占计数器，Android typed command 仅保留为证据，没有执行。所有五项的 replacement stream 以已消费语义身份被拒绝，没有第二次 HTTP 请求或工具作用。NEG07 的终态、provider-in、provider-out 和 claim 四份迟到前原件与迟到后实际文件逐字相等。

NEG06 的唯一实际合成 HTTP 请求约 1.040 s 后返回 model_timeout 原失败帧，business_verified 保持 false。实际 HTTP worker 退出 -15，原 wait 和进程组消失有原件；测试 server 观察到原连接关闭、没有发送响应且 slot 空闲。保留的模型健康记录仅发出一次请求、失败 fence=1，未重试、切换账户或模型，接受过的 claim 仍存在。没有真实模型推理或手机输入。

## 来源绑定与保全

独立读取器保存 615 份文件、2,383,187 bytes：两组完整原结果清单、冻结 source/input 材料、两份原 job 的 child/started/exit/witness/launch/stdout/stderr。读取包含九项文件元数据前后核对、完整 SHA-256 和目录清单核对。六份 synthetic-only-api.key 的内容没有读取或导出。

当前 15 份生产源码分别与 R6 实际 release-source-chain 的 FINAL-INTEGRATION-INPUTS descriptor 相等；配置和 service inputs 与其 SOURCE-BINDING 相等。五项 host package manifest 为 `594dcdb0a83028c2d11f9ed90585cb93fd47c982cfcba7127fb7686ace0b2368`，NEG06 package manifest 为 `e73b631a88949d4c7cae59d0b31f3624beb5264a126cea7c630bc54d169ceae4`。NEG06 绑定的 R6 combination 为 `7969a11bebda7f5eb788fd581bd9372d43c86d2251d0180cc3d5421c90956411`。

五项 source 与 input 的独立原验证器在 Pocket4 只读重建结论，与原 HOST-VERIFICATION 对象完全相等。本地另对完整原件、source15、配置、service inputs、原 job 归属、资源、迟到前后原件和 NEG06 实际 wire/worker/server/claim 进行 801 项检查，全部通过。第一次本地读取器将不同阶段的 worker_cleanup 摘要误认为同一字段集合，发生 KeyError；该失败保留，修订后直接核对实际 HTTP-WORKER-CENSUS 原件，没有重跑任何用例或改动原件。

## 资格边界

本报告增加的是可复核主机层结果。NEG04/05/07/08/09 仍分别需要 physical_native_task 层；BUILD、安装、四角色 READY、实际安装 source15 绑定、业务 E2E 和 19/19 没有由此成立。五项 host material seal 明确不是 deployment seal。此次没有执行或重复 NEG10—14。

这里的延迟是一次合成主机测试的耗时，不能作为手机 CPU 模型延迟、峰值内存、温度、电量或能耗结果。已记录的 maxrss 是进程累计峰值，原件明确不是每项 case 的独立峰值。

## 可公开小证据与完整原件

- `HOST-NEGATIVE-PUBLIC-SUMMARY.json`：六项结果、来源和边界。
- `HOST-NEGATIVE-INDEPENDENT-REVIEW.json`：完整 801 项检查及原件引用。
- `READBACK-MANIFEST.json`：615 文件的原路径、bytes、SHA-256。
- `READONLY-VERIFY-RESULT.json` 和对应原 status/read 回执：五项当前原件复核。
- `EXPORTED-ORIGINALS.json.gz`：完整原件的 gzip JSON，保存精确原字节；不含 synthetic key 内容。
- `originals/`：解包后的精确原文件；`verify_preserved_host_originals.py` 为本地只读核验源码。

所有历史失败、UNKNOWN 和原请求身份继续保持原义。
