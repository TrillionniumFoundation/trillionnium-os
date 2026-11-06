# source publisher v2：修复 JSON 往返后的 descriptor 键序

本包保留实际 v1 失败，并提供只改一行的独立 v2。没有放宽完整源码、字面量变更记录或全文件逆向检查。四份内嵌 payload、prepared consumer、prepared constructor 和两个目标路径保持原字节不变。

## 已发生的 v1 失败

Root 的实际进程 `1a1b1f3d1a6-fc05-7bb2` 以 exit 1 结束，stdout 0、stderr 207 字节，双 EOF，无超时、取消或自动重试。异常为 `only exact complete source input literal binding`，位于 `publish_binding` 之前。完整 145716 字节原回执保存在 `reference/ACTUAL-PUBLICATION-FAILURE01.original.json`，SHA256 `e963df18de341050db9df5f52eec573d835c0053fd3270f38825403cd2bd92d3`。

Root 随后独立只读核实两个目标目录均 ENOENT（job `1a1b1f6b757-fc05-7bc4`，exit 0，stdout 505/stderr 0）。其原失败 durable key 已消费。v2 使用新的 source pin 和新 key；不重发原请求，不覆盖已有目录。

上轮静态审查遗漏了把 proof 从排序 JSON 加载后实际走完整 `main` 的路径。保留该静态记录供追溯，本包新增实际 main 路径控制验证这个具体缺口。

## 精确原因与一行修复

| 步骤 | descriptor 插入顺序 | 生成的完整 constructor |
| --- | --- | --- |
| 准备阶段 `put()` 返回值 | path、bytes、sha256 | 34103 B / `342cf03f11fcb6cc02fd98f68f44a567603389788de45999c6182ad0a4426c5a` |
| v1 从 `sort_keys=True` proof JSON 加载 | bytes、path、sha256 | 34103 B / `d0012435248e5e0a72f4fde226939b2ca867a59fa5349dd8ad857fa38845a851` |
| v2 从准确输入 bytes 与目标路径调用 `located()` | path、bytes、sha256 | 精确回到 prepared 的 `342cf03f…` |

两个 descriptor 在 Python 结构上相等；`Changes.rhs` 写入的是 `repr(dict)`，所以源码原字节不同。原字节 gate 正确拒绝了它。

唯一变更：

```python
# v1
change.rhs('FROZEN_INPUTS', proof['source_inputs'])

# v2
change.rhs('FROZEN_INPUTS', located(binding_root, 'SOURCE-CHAIN-INPUTS.json', inputs_raw))
```

`located()` 与准备阶段采用相同的 path→bytes→sha256 构造顺序；字节数与哈希从完整实际 `inputs_raw` 派生。后面的 `constructor_raw == prepared_raw`、完整 `constructor_change` 相等和一条变更检查均保留。`SOURCE.patch`、`DIAGNOSIS.json` 与 `DERIVATION.json` 保存具体原文差异与全文件反演。

v2 为 141651 字节 / `477bb8c20d4868428761e403456e9c8b333b72607c8ff51aac404b2429dda342`。反向还原完整 v1 的 141612 字节 / `d6bfac4486ccd444bfe9ee98f1d1536b6453751200677d6bee5c6f5698360a27`。未改变 payload 390745 字节 / `486b5e5c2e05518306eef422194a081f2c2219f9154c9020859da807a62d9486`。

## 实际 Mac 控制：只到首次发布边界

只增加必要的两条完整 `main` 路径控制，实际 job `1a1b1fc1cf4-fc05-7be1`，exit 0，stdout 6172/stderr 0，完整双 EOF 和持久终态，无超时/取消/重试。

1. 加载完整实际 v1 入口，在真正 JSON 载荷解析及实际 pinned Mac 原件读取后，重现同一个完整 constructor 字节拒绝；writer 工厂尚未调用。
2. 加载完整 v2 入口，经相同真实 JSON 往返、实际原件读取、两条完整逆向和所有原 gate，准确到达第一个发布边界；所持 constructor 为 prepared 的 34103/342cf03f…。

测试进程唯一拦截的是 `writer()` 返回的实际写入函数：它记录已准备的八份文件，随即抛出明确的 test-only sentinel。原 `writer` 的函数抽取与完整逆向仍实际执行，实际写目录函数从未调用。没有替换源 pin、JSON parser、`Changes` 或任何 byte gate。两次之后两个目标仍不存在。

这证明具体修复覆盖了真实失败路径；**不代表实际 source publication 或后续 `derive_reviewed_source_chain` 已执行成功**。原 43 项 source-chain 控制保持原计数，不与本次两条路径相加。

控制完整结果 `controls/RESULT.original.json` 为 6172 字节 / `35254746adb4466f2ce07ca39953a01d10415ff337502378071a27160c29f5c3`；原终态/流复核 `controls/TRANSPORT-VERIFICATION.json` 为 1332 字节 / `549dd215d6a173b402dfa38133be6d7419c50a8042fd08a001cd270742f986d8`。完整 harness、请求及原 start/status/read 均保留。

## Root 可执行的精确新请求

`REQUEST.UNEXECUTED.json` 142103 字节 / `92dbdc0d728efa903a7203ead2deafdb1272fb662c857ba97ff3f0e6ef263bec` 是可直接交给 `process_start` 的完整对象，包含实际 v2 全文 stdin：

```json
{
  "host": "mac",
  "executable": "/usr/bin/python3",
  "args": ["-I", "-B", "-", "--publish-source-candidate-once"],
  "idempotency_key": "fc33-release-source-990-publication-once-02",
  "timeout_seconds": 180
}
```

上方为了阅读省略了完整 stdin；实际文件没有省略。保持 root 已选定的 990c runtime、原八项 material source input 与两处尚不存在的输出目录。入口只能创建这两处新主机源码目录，第一处八文件，后者调用纯源公共构造器后输出 14 源及说明性原件。它不执行 phone、sender、BUILD、install、READY 或 Git 动作。

若未来实际派生或第二目录发布失败，第一处目录可能已存在，必须保留原状态和控制器原件；入口不会删除、覆盖或自动重试。任何实际 source publication 结果由 root 的新进程原回执单独决定。本包中的 case、BUILD、install、READY 仍未绑定。
