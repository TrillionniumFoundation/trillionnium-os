# r4 原失败动作恢复阶段

这份快照记录 Root 对原 Visual04 动作追加的退役恢复记录。原任务仍为失败，恢复不改变业务分类，不增加业务样本分母，也不计入固定 19 项成功数。

## 原始证据

- RESOLUTION.json：1,237 字节，SHA256 7e06216823c49ec8b3949efa334e61b6731ca3f9bd4a039edbea771fb849a433。
- APPEND-RESULT.json：3,454 字节，SHA256 561a103255d3eba6b6ebae62f8c8b015b51e5a93357947232acef51e11d6dda5。
- 原 15,100 字节 retirement proof 保留 SHA256 2bdd6c33c42359f1b27567b99627f7223d40a0c37f6af0158b8dc010e899943e；其中 resolution_written=false 是追加之前的历史事实。
- CHECK-RESULT.json 是追加前只读检查；INSTALL-PROVIDER-R5.json 记录 24 个文件安装和读回，不代表服务已经启动。
- Main 的严格 SSH 同字节镜像 manifest：9848803a09e4413def488726053637d7f8701c7d360d791dcb95bf3d719a582e。镜像只读原文件，O_EXCL 创建新副本，随后由独立文件工具完整读回；没有解析再重写原 JSON。

## 状态与统计

实际追加后的独立 reader 记录 unresolved=0。原 24 条 claims、原 intent、原 client result 和 native provider_failed 均保留。恢复期间无新模型请求、工具 effect、界面动作或策略写入；原请求、文本、动作均未重放。

r4 健康样本维持 2（1 通过、1 失败），业务样本维持 1（失败），固定 19 项为 0 项关闭、18 项未运行。新 r6 原生组件、新 provider-r5 健康和业务必须使用独立分母。本快照截止于实际 resolution 追加，不包含随后可能发生的新组件或策略运行。

provider-r5 的 24 个 payload 文件已安装并校验 SHA；安装记录明确 service_starts=0。新模块仍不是可启动封包：需要实际组件资格、最终策略与标签/DAC、模块冻结及全新健康请求。冷启动、脱离 Mac/USB、视觉业务、Unicode 业务、外屏、横屏和折叠切换均不因恢复而获得资格。

## 保留与公开范围

已有 r3/r4 health/business 阶段快照及追加前 working 草稿均保留原样。公共投影不含用户草稿、任务原文、密钥或密钥 hash、运行实例 PID/boot ID。私有快照与原件镜像供独立核验。报告生成器没有操作手机、调用模型、执行 resolver 或发布文件。
