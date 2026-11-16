package org.trillionnium.hepta.local;

/** Presentation only. Raw session/results and advanced diagnostics remain unchanged. */
final class TaskDisplayText {
    private TaskDisplayText(){}
    static String forStatus(String raw){
        if(raw==null)return null;
        if(raw.startsWith("native target, ancestor or outside recommendation node changed: ")
                ||raw.startsWith("native target, ancestor or non-carousel node changed: ")
                ||raw.equals("AX/DOM bracket changed; no current page capability published"))
            return "网页内容发生变化，本次未取得可核验的结果。请稍后重试。技术详情保留在高级诊断和任务记录中。";
        if(raw.equals("initial page commit wait exceeded its original deadline"))
            return "网页尚未完成加载，本次查询未完成。请检查网络后重试。技术详情保留在高级诊断和任务记录中。";
        if(raw.equals("readonly Flight observation cancelled or expired")
                ||raw.equals("read-only content wait exceeded its original deadline")
                ||raw.equals("evidence RPC deadline exceeded"))
            return "网页观察超时，本次未取得可核验的结果。请稍后重试。技术详情保留在高级诊断和任务记录中。";
        return raw;
    }
}
