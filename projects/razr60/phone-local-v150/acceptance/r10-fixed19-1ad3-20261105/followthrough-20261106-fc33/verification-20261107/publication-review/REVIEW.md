# 独立发布审查

结论：需修正 1 处公开脱敏遗漏；未发现将 UNKNOWN、清理或源码回归升级为整项手机资格的表述。

## 必须修正

`verification-20261107/CONTROLLER-RECONCILIATION.PUBLIC.json` 的 `status_query_original.content[0].text` 和 `log_query_original.content[0].text` 仍含配置的 SSH target。metadata 已移除该字段，但嵌套原错误文本未移除，与 README 的公开范围声明不符。应移除这两处别名，把对应字段标为 redacted，并保留原始材料 SHA256 和脱敏路径；UNKNOWN 结论继续不变。其余公开文件与云端回归归档未发现该配置别名、未脱敏 idempotency_key 或明确私有凭证/草稿/XML正文标记。

## 已核对

- 原 Mac job 与计划的完整 argv、plan hash、label/nonce 对应；公开 metadata 除声明的两项脱敏外与原字节解析值一致，包括超出 JavaScript 安全整数范围的 fingerprint。
- REVIEW 明确 `success_proven=false`、`zero_effects_proven=false`；缺失目录未被当作零效果证明。
- 前次67文件、9目录成功与后发0效果拒绝分开记账；host exit0 未覆盖 phone rc1。
- 三组公开回归通过与 `--require-actual` exit1 分开保留，整项资格仍0。
- 908个归档文件、2,514,217原始字节及归档自身 SHA256 全部符合清单；所有4个 run 的 result/run/stdout/stderr 副本与声明的长度和hash一致。
- recovery 完整性清单22项逐字节匹配；本次 verification README 的9条相对链接均存在。

## 尚未独立证明的范围

允许读取的 delivery_repo 是发布增量目录，未含 .git 或原父 README 的基准副本，因此能确认历史段落被标为 checkpoint09，不能在此数据范围内独立证明历史正文逐字节保持。未把这一限制说成已发生修改。Section 4 的 pending placeholder 按 owner 指示留待其他代理完成，本次不作为最终缺陷。

未执行远端工具，未修改导出文件。只在独立 publication_review 中保存检查结果。
