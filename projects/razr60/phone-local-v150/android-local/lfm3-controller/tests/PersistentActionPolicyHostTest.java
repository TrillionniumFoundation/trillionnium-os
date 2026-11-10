import org.trillionnium.hepta.local.PersistentActionPolicy;

/** Real pure-Java policy checks, including the observed popup and calculator labels. */
public final class PersistentActionPolicyHostTest {
    private static int assertions;
    private static void verify(boolean expected,String text,String description,String child,boolean inputLike) {
        PersistentActionPolicy.Decision value=PersistentActionPolicy.evaluate(text,description,child,inputLike);
        if(value.allowed!=expected)throw new AssertionError("Unexpected policy for "+text+" / "+description+" / "+child);
        if(!expected&&(!value.reasonCode.startsWith("persistent_")||!value.detail.startsWith("guard:")||!value.detail.contains("未点击")))
            throw new AssertionError("Rejection must have an explicit non-dispatch reason");
        assertions++;
    }
    public static void main(String[] args) {
        String[] rejected={"清除历史记录","清空搜索历史","删除这条记录","清除应用数据","清理缓存","删除文件",
            "删除账户","移除联系人","擦除所有内容","重置网络设置","格式化磁盘","注销账号","卸载","卸载更新",
            "恢复出厂设置","出厂重置","清除瀏覽歷史","刪除檔案","清除快取","移除帳戶",
            "Clear history","CLEAR SEARCH HISTORY","Delete files","Remove account","Clear app data","Wipe device",
            "Erase all content","Reset preferences","Format disk","Uninstall updates","Factory data reset","Restore factory settings"};
        for(String text:rejected)verify(false,text,"","",false);
        String[] unclassified={"C","AC","CE","清除","删除","清空","Clear","Delete","Clear current input","清除当前输入",
            "清空输入框内容","删除最后一个字符","设置","应用","应用管理","特殊应用权限","历史记录","Files","Account settings",
            "取消","取消删除","不删除","Cancel","Don't delete","保留数据","Keep data"};
        for(String text:unclassified)verify(true,text,"","",false);
        // The exact observed bad structure: blank clickable parent, actual child label.
        verify(false,"","","清除历史记录",false);
        verify(false,"","清除历史记录","",false);
        verify(false,"清除","历史记录","",false);
        verify(false,"历史记录","","清除",false);
        verify(false,"C","清除历史记录","",false);
        verify(false,"清除当前输入","","清除历史记录",false);
        verify(false,"取消","","清除历史记录",false);
        verify(false,"ＣＬＥＡＲ　ＤＡＴＡ","","",false);
        verify(false,"清\u200b除历\u200b史记录","","",false);
        // Real Motorola buttons have empty text and bare descriptions, not C/AC text.
        verify(true,"","清除","",false);
        verify(true,"","删除","",false);
        verify(true,"C","清除","",false);
        verify(true,"AC","Clear all","",false);
        verify(true,"清除历史记录","","",true);
        verify(true,null,null,null,false);
        System.out.println("PersistentActionPolicyHostTest assertions="+assertions);
    }
}
