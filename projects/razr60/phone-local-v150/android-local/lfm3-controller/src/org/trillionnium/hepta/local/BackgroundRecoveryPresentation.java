package org.trillionnium.hepta.local;

/** Presentation only; this class never grants recovery or starts work. */
final class BackgroundRecoveryPresentation {
    final boolean visible;
    final String title,message;
    private BackgroundRecoveryPresentation(boolean visible,String title,String message){
        this.visible=visible;this.title=title;this.message=message;
    }
    static BackgroundRecoveryPresentation from(boolean running,boolean recovering,boolean lease,
            boolean blocked,boolean canAcknowledge,String unavailableReason){
        if(recovering)return new BackgroundRecoveryPresentation(true,"正在核验上次会话",
                "请等待核验完成，再按提示继续。当前不会开始新任务。");
        if(running||(!lease&&!blocked&&!canAcknowledge))
            return new BackgroundRecoveryPresentation(false,"","");
        if(lease)return new BackgroundRecoveryPresentation(true,"第 1 步：清理上一次后台空间",
                "核验完成后，再确认中断并建立新会话。原任务不会自动重做。");
        return new BackgroundRecoveryPresentation(true,"第 2 步：确认中断并开始新会话",
                canAcknowledge?"原任务记录会保留。确认后只建立空闲会话，不会自动开始任务。":
                        unavailableReason==null?"上次会话的恢复条件尚未满足，请查看当前状态。":unavailableReason);
    }
}
