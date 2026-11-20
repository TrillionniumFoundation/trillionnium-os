# 第 26 案：LFM2.5-8B-A1B 首个捕获未稳定，模型选择提前结束

**历史状态说明：本文截止第 26 案。** 文末“目前尚未修改或验证该行为”只描述该案结束时的状态。后续已在 bc683d 构建中完成两文件修复及主机侧资格核验，详见 [最终报告的 bc683d 复测章节](README.zh-CN.md)。第 27 案没有触发新增 pending 提示或 initial-unavailable 重读分支，因此仍无这些新增分支的真机触发证据。原第 26 案失败结果保持不变；本文不代表最终安装和配置状态。

同一 ff0a APK、机票目标、480 秒宿主观察上限（应用原期限不变）的后台测试仍未完成。实际加载资格已确认：LFM2.5-8B-A1B Q4_0，权重 4,844,678,368 字节，SHA-256 48ed1465d761311b2fd57b7fb46cf969a20b3a8281945b04e10f52bd1609e715；原生回执为 HTP0、上下文 8,192、四线程，无自动 CPU fallback。核心日志另记录 HTP0 设备和 25/25 层 offload（日志沿用“GPU”统称，实际选定设备为 Hexagon）。这确认了本次真实模型加载和正常生成，不代表业务通过。

唯一一次模型调用正常 EOS 完成，输入 3,446 token、输出 117 token。原生精确上下文预算为 3,958/8,192，接受通过；app 耗时 33.726 秒，native 耗时 28.530 秒，其中包含首次 hash 与加载。该次 pp 506.36 token/s、tg 15.02 token/s、TTFT 6.852 秒；这是一次冷启动请求的观测值。无 native error、超时或取消。最后动作排空时，原任务仍余 436,584 毫秒。

## 页面与决策的实际因果链

首次首页 DOM bracket 变化后，控制器已经进行一次只读重观察，使用原固定 32 秒预算。随后第二次 capture 返回 unavailable，原因为“DOM changed across visual callback”。既有 WebFlightSession 对此分支立即发布等待域，保留身份绑定并不给点击权限；当次 observe 返回时，固定阶段截止尚余约 28.9 秒。模型所见 phase 为 official_page_capture_pending、nodes 为空、allowed_click_ids 为空，grammar 只允许 wait 或失败/部分 done。

模型没有选择 wait，而是 done(failure)，称搜索结果未加载并缺少航班信息；其 reason 还提到搜索框和结果列表，这些不在实际模型输入的节点或可见文字中。该动作 accepted=true、dispatched=false、stale=false；总共零次 click、没有进入城市/日期选择，也没有 query 派发或航班结果。

存在一项准确的代码提示因素：等待域原先写明“官网证据尚未稳定；只可等待或报告未完成，不能点击、输入或宣称查询成功”，但 withProgress 在没有城市确认时，将 official_page_capture_pending 的 next_goal 覆盖成“先选择并读回出发城市与到达城市，再选择完整年月日”。当前工具仍无任何点击能力，因此这是阶段提示不一致，并未放宽授权。已修复的 official_home 保留分支没有涵盖该 pending 阶段。

模型结束后的最终独立观察已识别为 official_home，并验证了 n38“机票预订”入口和正确首页 next_goal；该帧没有再送入模型。它证明页面后来提供了可验证入口，不能倒推模型先前已拥有合法 click，也不能保证若选择 wait 就必然成功。

## 比较与验证范围

这轮是同 APK、同目标的独立运行，但不是与第 25 案最后 query-ready 输入同阶段的纯模型比较。第 25 案 LFM3 在已有合法“查询”目标时提前结束；本轮 8B 在捕获未稳定、仅允许 wait/done 时提前结束。不能用这两个不同状态直接判断 8B 的合法点击能力或一般规划质量更差。

本轮新增 bookingPending 16 秒分支未触发；新 typed 预派发恢复也没有触发。原失败结果保留。清理、身份绑定与焦点细节由独立总账审阅覆盖。本审阅仅读取已完成原件，没有改源码、生成候选或执行手机操作。

源码依据：WebFlightSession SHA dd45a9b72319bdc52a78152b13f62a849914d97b83146afb7435581a86fa6286 的第二 capture unavailable 发布等待路径，以及 WebFlightDomain SHA c61938db4efa4df6faa33de2be23e8bfc9086fe95bcb6af0269f6d98505bfc01 的 waiting 文案与 withProgress 分支。下一项可验证工程问题是 pending 阶段的准确提示及其有界只读恢复资格，保持所有身份、DOM、native 和动作门槛；目前尚未修改或验证该行为。
