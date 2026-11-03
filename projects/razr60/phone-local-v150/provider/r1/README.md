# RAZR60 phone-local provider v150 candidate

此目录是新的、可迁移到手机 GNU Python 3.12.3 的标准库 provider 源码。它没有自动部署、自动发任务、自动重试、额度轮询或模型回退。所有真实手机动作仍由 Root 唯一操作人启动。旧 v149 原目录及其 claims、合约和证据均未修改。

## 运行路径

正式入口为 source/daily_phone_local.py。它继承 v149 的 durable semantic admission、one-use contracts、native frame序号、effect dispatch/receipt、typed screenshot/Unicode/public readback/HEPTA return 和业务后条件逻辑。新增 completion 只向已核实的手机本地 llama.cpp HTTP 服务提交一次请求，模型为 GUI-Owl-1.5-2B-Instruct Q4_K_M + Q8 projector。

source/provider_phone_local.py 以受限 HEPTA JSON schema 获取模型决策。GUI-Owl 官方 mobile_use prompt 只作为独立对照资料；本实现没有运行官方示例中的云端 App resolver 或自动 ADBKeyboard 切换。0–1000归一化坐标必须映射本轮真实 JPEG 的 encoded尺寸，再进入原截图/像素/焦点守卫。模型不能选择任意 shell、ADB命令或客户端路径。

source/phone_local_http_worker.py 是每轮单独的HTTP客户端进程。它只访问数字loopback、禁止重定向、不自动重试、不读凭据环境；API key只从0600私文件读入 Authorization header，不写进参数或证据。原始响应、usage、timings、finish_reason及request SHA均保留。length会明确报告model_budget_exhausted。只有stop、正确model标识、合法schema、有效业务后条件才可能得到完整业务成功。

这份候选支持两个显式 executor 配置：

- phone_local_sidecar：正式手机路径；native shell.exec以argv直接执行已固定hash的rootfs Python tool_client，经抽象UDS连接Android Bionic sidecar。真实事件标记shell.exec，绝不伪装adb.exec。
- adb_legacy：过渡诊断配置；推理可在手机，控制面/执行链仍可能在Mac/Pocket4。它不能作为整机脱离电脑工作的证明。

原 daily_provider.py 保留为前版本源码，不是此版本运行入口；由于依赖已显式演进，它的旧pin会拒绝新依赖，不能借它启动旧云端CLI。

## 配置和入口

local-config.phone.template.json中的service manifest SHA占位符故意不满足配置校验；tool client已固定为经过独立验证的正式字节。local-config.phone.production.json是Root提供实际服务输入SHA后的正式配置，保存为0600私文件，不含API key值。Root在实际二进制、权重、服务manifest、tool_client以及设备读回完成后填写真实SHA，保存为0600私文件。已采用实机解析的两个普通App入口：com.motorola.cn.calculator/.Calculator 与 com.android.settings/.homepage.SettingsHomepageActivity。控制探针入口沿用已核实包。模型只能打开该registry中的组件；添加App需实际解析与单独验证。

建议部署路径由Root最后确认：

    /usr/bin/python3 -B /var/lib/trillionnium/owner-open/phone-local-v150/provider/source/daily_phone_local.py \
      --state /var/lib/trillionnium/owner-open/phone-local-v150/provider-state \
      --config /var/lib/trillionnium/owner-open/phone-local-v150/local-config.json \
      --port 18080 --workers 1 --timeout 120 \
      --retained-claims /var/lib/trillionnium/owner-open/phone-local-v150/retained-claims.json \
      --retained-claims-sha256 ACTUAL_RETAINED_CLAIMS_SHA256

state、evidence、templates、bindings均要求0700；所有配置、claim、合约、回执要求私有。迁移必须携带目前全部accepted claims和消费过的合约binding，不能只携带早期15条而漏掉后来的任务。模型健康单独写model-health-phone-local.json，不覆盖原gpt额度失败。ready.json只说明transport接受能力。

## 取消、超时和恢复

每轮先读取/slots，限定一个slot且is_processing=false才发新模型请求。idle slot可以保留旧id_task，因此不把非空id_task当作仍在处理。HTTP客户端join以后独立再读slot；slot仍忙或不可观察就停止接新任务。客户端退出不等于服务器推理已取消。模型client被杀也不撤销此前Android系统已接收的点击/输入。

原请求nonce、semantic identity、one-use template及effect identity永远保留。若存在旧spawn-intent没有joined，服务启动会拒绝，要求先检查原回执。旧结果不能改写已持久terminal。恢复先inspect原effect receipt与当前公开UI，再由新的授权、新nonce和只包含尚未完成部分的任务继续；不重放旧请求或未知效果。

仅有控制器脚本/fixture证明、/health返回200、CLI exit0、模型自述成功或native complete都不等于业务完成。Unicode完整任务须包括原文输入读回、确认后的公开原文与四行回执、实际HEPTA返回以及一致native终态。

## 已完成的离线验证

tests/local_provider_checks.py 的第一次运行通过87项断言，全部位于host_isolated_fixture层，包含单次HTTP终态/usage/slot证明，以及NEG-04至12和NEG-14子集。模型是专用loopback HTTP fixture；没有真实模型请求和手机动作。

tests/local_contract_capacity_checks.py 的第一次运行通过44项断言，补齐NEG-13与NEG-14：真实O_EXCL并发、错误scope不消费、旧nonce拒绝、真实文件rename竞态、未知IO错误、孤儿spawn阻断、稀疏文件容量边界、claim保留、父进程FD基线恢复。稀疏容量测试文件在取得读回后已移除；原证据不删。

合计两次运行131项断言，不是131个模型任务，也不是19项实机全通过。不可将fixture成功加入手机业务成功率分母。NEG-04/05/07/08/09仍需单独真实native生命周期复核。真正视觉、Unicode、计算器、设置、返回和显示切换的资格由Root后续全新运行决定。

## 固定19项协议

qa/fixed-acceptance-set.v149-original.json保存前版原规格（SHA07433e17cb71592a011a54c787ac61947b727ec5ae6f507bca22f8fa6dfb0736）。qa/fixed-acceptance-set.json派生新本地模型组合，保留全部4模型E2E、1直接组件、14负向的ID、业务后条件和边界，仅把原CLI证据条件显式适配为HTTP与worker/slot证据。

固定上限保留：8模型轮、最多7工具、单轮120秒、整turn300秒；图像单张196608字节、整turn393216字节、截图有效期120秒。不能为了让计算器或慢速本地模型通过而偷偷提高预算。预算不足、错误模型动作、Unicode不一致、缺少返回或缺失业务回执都记录真实失败或部分完成。

当前只承认原来的display0、portrait、1224×2992几何守卫。真实外屏/横屏/折叠切换尚不能由本源码文件或合成fixture宣称通过。任何扩大范围需要该物理状态的独立显示身份、坐标、焦点及恢复证据。
