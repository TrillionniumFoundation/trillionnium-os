# r7-r2 固定五项主机隔离故障样本

NEG04、NEG05、NEG07、NEG08、NEG09 各一个新 host_isolated 样本，5/5 主机层通过，154 条实际运行断言。它们仍分别缺少本组合要求的 physical_native_task 层，因此只合并这五条时固定 19 项是 **19 BLOCKED**，不授予日常使用资格。

## 实际调用与终态

Main、SSH、bwrap、原 frozen daily 与 HTTP fixture 的本次进程终态均核验。模型 HTTP worker 的真实 wait、进程组退出和 fixture 原 GET 读到的 idle 分别保留。三个 counter 是主机隔离进程的真实一次写入，值均为 1；没有执行 Android 命令、真实模型或原生手机 Host，不冒充手机执行器回执或 SELinux 资格。

- NEG04：模型在途原连接断开，原失败/未知终态保留；没有工具分派。
- NEG05：一次原 counter 已发生后断开，只读原 receipt，未重复效果。
- NEG07：原 counter 已写、receipt 迟到；原失败终态和 claim 保持不变，迟到结果不触发第二次分派。
- NEG08：工具前取消，原 provider 的 cancelled 终态、HTTP worker join 和 fixture idle 均实读。
- NEG09：一个原 counter 已完成并独立读回、wait 和核组消失后取消；未交付结果的原 ledger 保持保守未解状态。

每项还真实负测同一语义 identity 更换 stream 的重新准入：原 claim 拒绝，没有第二次 POST 或 counter。

## 组合与适配范围

本次严格绑定源码 7c20af425fa88cf6fd90aa7b902bd7c5c0cb0f1d4e808ac26ddbd4445f61c4ab、组合原件 ee2bba801325525f9fa910c2c613352b54c32cb71921f2e7a16d2f25205e94d4、canonical 1f4763e8bf56cf25392a944298d08e4284495b0b7f44b3edb77060a250b598c5 和新固定19协议 a9f314。13 个生产源、HTTP fixture、counter 和故障case控制流均保持原字节；只替换组合/协议/新独占输出目录以及必要传递 SHA。所有旧 r7-r1 和 r6-r2 原件保持原版本。历史手机取消槽位 busy 失败不是本组合的新样本。

## 时延与资源

实测内层 6.554076919 秒、外层 6.696569366 秒、Main/SSH 7.072137708 秒。各项 FD 4→4、线程 1→1；CPU 与 lifetime RSS 按原记录保留，lifetime RSS 不是每项独立峰值。未调用真实模型，模型 usage、金额和能耗均为 null，不能解释为零成本。

本次没有触发 90 秒告警或外层 105 秒 deadline；正常执行样本不能替代超时分支资格。原 sources 仍保留告警后不再启动后续 case，以及独立 owned-process 有界清理。

## 原件与分层统计

首次报告脚本在完成原件核验与聚合 exit0 后，因使用旧字段名 required_layer_results 而退出1；原失败保留。本独立收尾只读真实 required_layers，没有再次执行样本或聚合。

332 份原文件及一份原 manifest 共 617590 字节逐字节镜像并独立重算 SHA。五个合成凭据内容和摘要均未导出。ATTEMPTS 使用冻结聚合器的精确原件引用，实际聚合进程退出 0。公开投影不包含任何实际请求、nonce、草稿、密钥、scope、action/process ID 或原始 claim/native 历史。
