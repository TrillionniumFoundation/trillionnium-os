# r7 固定五项主机隔离故障样本

NEG04、05、07、08、09 各一个新 host_isolated 样本，5/5 主机层通过，154 条实际检查。Main/SSH/bwrap/内层真实 exit0，五个 HTTP fixture、五个 frozen daily 与三个 counter 子进程均实际 wait/exit0/组消失。HTTP worker 的预期取消退出单独记录，不等同服务端槽位释放；本次 fixture 的原 GET 确实观察 idle。

原 r7 的13个生产源码只读载入，完整组合 7c20/ab038/87609 与固定19 d68dd5 被核验。fixture 仅将原 flat open 响应改成冻结 r7 的 mobile_use named JSON；实际 model-action、mapping、legacy decision 和唯一 native call 的绑定均从原运行记录核验。Android命令未执行，三个一次性 counter 是独立隔离主机进程的真实写入，不冒充手机执行器回执或SELinux证明。

NEG04/05 原连接在各自规定相位断开，wire未收到终态的事实保留；原文件真实失败/未知而非成功。NEG07 原counter已提交而receipt尚未产生时提交unknown，原turn.fail后迟到结果不改变原终态/claim，也不触发第二次效果。NEG09先读原counter receipt并wait/核组消失，再取消未交付结果的原任务；未解除未知phone action ledger。五项都显式负测相同语义identity更换stream被原claim门拒绝，无第二次POST或counter。

实测内层6.748秒，外层6.902秒，Main/SSH7.362秒。FD各项4→4、线程1→1，CPU和lifetime RSS逐项原样记录；后者不是独立每项峰值。未加载真实模型，真实模型usage、金额和能耗为null。旧r6-r2源码/样本和物理NEG08槽位busy失败不被改写或混入r7分母。

新harness仅增加“绝对90s告警已发生后不再启动后续case”，修复旧逐case处理可能继续的控制流；本次没有触发该分支。outer105s加有界owned清理仍独立，不能将正常样本当普遍deadline资格证明。

333份原件617588字节逐字节复制、独立SHA读回，5个合成凭据的内容与摘要不导出。ATTEMPTS使用冻结聚合器要求的精确path+sha256引用，实际聚合进程exit0。仅这5项host子集时固定19全部仍BLOCKED：每项host PASS，而其必需physical层未执行。该结果不授予日常使用资格、不生成下一Send、不重放旧任务。
