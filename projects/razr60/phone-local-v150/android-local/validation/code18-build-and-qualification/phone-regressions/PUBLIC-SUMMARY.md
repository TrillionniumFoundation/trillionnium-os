# Code18 LFM3：四项手机任务公开摘要

**严格结果为 0/4。62/62 次本地 native 推理完成并有正向 HTP offload 证据；这没有使任务判定通过。**

配置：LFM3-1.7B QAD Q4_0，NPU，8192 context，4 threads。原 verdict 与全部断言保留。

## 逐项结果

| 原测试 | 结果 | 步数 | 主机耗时（秒） | 模型运行窗口内资源样本 |
|---|---|---:|---:|---:|
| 计算器按键 | FAIL | 20 | 235.392 | 14 |
| 设置→桌面→设置 | FAIL | 20 | 239.169 | 14 |
| 跨应用顺序 | FAIL | 2 | 33.575 | 1 |
| 查找并打开计算器 | FAIL | 20 | 254.049 | 15 |

计算器、有序导航及查找任务达到20步上限。跨应用任务在先发生顺序/目标错误后，遭遇稳定观察失败。四项均已知清理完成；find 的原目标谓词通过也没有升级未正常完成的原任务。

## 调用时延与吞吐

SDK TTFT 不含每次完整模型校验和创建时间；它不是用户发出指令到手机首次动作的时延。

| 指标 | n | 最小（ms） | 中位（ms） | 最大（ms） |
|---|---:|---:|---:|---:|
| native完整调用 | 62 | 7599.688 | 9134.294 | 14884.890 |
| App调用 | 62 | 7730.000 | 9251.500 | 15038.000 |
| SDK TTFT | 62 | 1774.377 | 2025.143 | 2704.881 |

| native阶段 | n | 中位（ms） | 总计（ms） |
|---|---:|---:|---:|
| hash | 62 | 895.770 | 55379.483 |
| vocab | 62 | 273.135 | 17105.165 |
| create | 62 | 1361.077 | 86070.788 |
| template_tokenize | 62 | 72.828 | 10597.790 |
| generate | 62 | 6399.136 | 408750.911 |
| destroy | 62 | 99.017 | 6840.116 |
| deinit | 62 | 0.039 | 4.090 |

完整权重校验+创建合计 141450.271 ms，占 native 总时长 24.07%。这是实测成本，不能当作复用模型后必然获得的加速比例。

Prefill 加权吞吐：945.958 tokens/s；使用 62 次调用的总 122266 tokens / SDK总 129250977 μs 计算。

Decode 加权吞吐：25.041 tokens/s；使用 62 次调用的总 6988 tokens / SDK总 279061138 μs 计算。

HTP层数、正模型buffer与完整回执支持正向NPU执行；不证明所有算子均在NPU执行，也没有测量利用率或功率。

## Current HAL 温度与内存

共 74 个资源样本，51 个落在完整suite区间；名义间隔15秒，样本起止包围全部四项。只解析 Current temperatures from HAL，排除cached温度。

| HAL类别 | 读数数 | 最小（℃） | 中位（℃） | 最大（℃） | 最高sensor status |
|---|---:|---:|---:|---:|---:|
| CPU | 408 | 33.80 | 46.10 | 62.60 | 0 |
| GPU | 408 | 33.40 | 43.00 | 52.60 | 0 |
| NSP | 357 | 32.60 | 44.60 | 54.20 | 0 |
| battery | 51 | 21.00 | 25.00 | 27.00 | 0 |
| skin | 51 | 24.08 | 34.12 | 37.35 | 0 |

| 内存指标 | n | 最小（MiB） | 中位（MiB） | 最大（MiB） |
|---|---:|---:|---:|---:|
| 系统MemAvailable | 51 | 6385.56 | 6585.27 | 8729.41 |
| 同App UID进程RSS之和 | 51 | 155.29 | 494.95 | 528.13 |
| App主进程RSS | 51 | 155.29 | 186.24 | 213.63 |
| 其它同UID进程RSS | 38 | 7.91 | 317.51 | 340.79 |

HAL读数数包含同类别的多个传感器。采样不能证明连续峰值；进程RSS可能重复计入共享映射，也不等于NPU总内存。未据此推断耗电或降频。

## Find 历史裁剪因素

模型先完成 find_app→open，此后18次重复只读查找。当前25个节点完整；但最初find调用的显式历史被独立1024字节上限裁掉，dispatched序列按原设计不收录只读调用。两条真实历史共1047字节，只超23字节；保留两条时上下文保守上界7387/8192，仍有空间。搜索结果可见但缺少明确调用来源/先后身份。这是已证实的集成因素，不是唯一原因的证明，也不改变FAIL。

## 网络、清理与结论边界

原offline wrapper为completed_and_restored；离线前置状态和恢复均两次核实，原无线偏好与默认连接恢复，错误为0。4/4 case清理已知、62/62 native退出已观察，durable terminal完整。功能suite退出码3来自任务失败，supervisor没有超时。

wrapper 的 phone_cleanup_known 字段实际为 null，原样保留。4/4 case 的已知清理来自各自验收记录，不能把空字段补成全机clean=true。网络状态为采样检查，不是全程抓包；不声明当前手机状态。普通Start、Stop、重启、锁屏/熄屏及广泛App能力属于其它验证；不同context/提示/初始与温度条件不能直接当作同工作负载模型排名。

## 可追溯身份

公开文件只含字段白名单、原测试指令、数值及摘要哈希。原始手机文本、任务/运行ID、私有请求秘密、序号、路径、截图及应用清单均未导出。

- original_statistics: 89d54549601e8645d2822f629b6500332e0997fed1a95c856aa42f84f20d0d6e
- complete_private_input_hash_manifest: fc94236c361c8edf2a8f39eb48086f6242efff43b9673da0a8b28df06308dee9
- original_statistics_artifacts: 2591ca164e76b21c6a85ed06443876f2fbd2b7eef38fc575ba1a1e1f6bd4e8f1
- original_statistics_collector: 34e36e662f10f137c2def849e121576e62a93276ededfc1e45f3cae74e875b05
- current_hal_projection: 822cb582c7f0fc138ae754e0b9eec64c8f9df346d341c59afbb6d7da64723173
- causal_audit: 94f77b79add3f67be2fae80a5cf5cb2df985d607639408f221b85cf784f119e8
- frozen_test_plan: e1406afd7b6796e46d4af4f5de3a2bbabf849990c695b1ea8fd32c67eb6c0f80
- original_core_assertions: 65999f565846afda7ff7ba75dee4eff1cc4e32a29f670b9182039139eec0d836
- suite_result: 17c5b44434cd550ec9a898e9c555bfbdb70d462f6a8faf23199dad742c9d8c3f
- offline_result: c28b51d5aa8f952e1efc9f23ad22b6af08a42ca55130e39026fed9ce17af7ba9
- raw_telemetry_samples: 6dae857878f96df000dc0141aca7960092ac596b76817d23045297264d80a483
