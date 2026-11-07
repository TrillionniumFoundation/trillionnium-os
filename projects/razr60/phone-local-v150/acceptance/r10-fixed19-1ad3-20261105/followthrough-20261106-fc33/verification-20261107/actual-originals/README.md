# R6 actual 原件复核追加结果

先前公开包中缺失的私有原件已从保留 operator 包按精确路径只读取得。在新的隔离副本中，原样的 `test_native_streams_v3.py` 带 `--require-actual` 实际退出 0，状态为 `READ_ONLY_ACTUAL_ORIGINALS_VERIFIED`。这闭合了本次 archived-original parser/consumer 复核 gate。

## 核验依据

- Schema 为 16924 字节，SHA256 `76ec7ca00770c6ec66db6fb9919bfb15145de670d690b5f61b30a3b047df695c`。
- 13 个成员共 569919 字节，逐个完整 SHA256 与 schema 全符。大文件每段同时核对 chunk SHA 和固定 version。
- 新副本中的 40 份公开包输入与先前固定提交逐字一致；14 份私有输入（schema 加 13 成员）在运行前后也未改变。
- 新 RESULT.json 为 61075 字节，SHA256 `4d96fb7665d3e5933112db0a41eaed4654e5686454b0c7578eba02691bdba3ea`。stderr 0 字节，无超时，无 audit denied，FD/thread/child CPU 回到实测基线。
- Native 分组保持 parser 73、consumer 12、trust parser 40、trust consumer 11、dispatch binding 9；ledger binding 通过。实际 capture 与 guard 的三个 preimage 公式和完整回执均一致；原 guard exit 70 仍被拒绝。

最初 `native-require-actual-01` 的 exit 1 保留，未改写为成功。原 `acceptance_review` 的 970 个 manifest 成员、manifest 本身及 RUN-SUMMARY 均重新验证为原字节。本次为新增、独立的 `native-require-actual-retained-01` 记录。

## 公开边界

本目录只包含描述符、计数和复核结论。原 schema、13 个原始成员、传输分段、实际 RESULT 及其原始日志均保留在独立私有目录，未加入公开文件列表。公开文案由固定 metadata allowlist 构造，并检查了原 owner request 与 capture payload 未被包含。

Phone/model/native dispatch 均为 0；没有启动新手机任务、输入新 nonce 或重新执行业务。这是使用当前 R6 相同 15 源读取历史原件的复核，不是当前 NEG01 物理闭环，也不关闭 BUILD、安装 READY 或任何 fixed19 整项。

## 复现命令形态

```text
python3 -I -B <isolated-private-package>/test_native_streams_v3.py --package-root <isolated-private-package> --out <fresh-private-output> --require-actual
```

精确 argv、保留原件来源、每段 version、原始日志与完整结果在私有审阅材料中。公共摘要为 `ACTUAL-ORIGINALS-RECHECK.PUBLIC.json`。
