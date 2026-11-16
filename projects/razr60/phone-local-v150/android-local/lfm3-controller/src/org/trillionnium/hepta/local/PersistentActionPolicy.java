package org.trillionnium.hepta.local;

import java.text.Normalizer;
import java.util.Locale;
import java.util.regex.Pattern;

/** A narrow executor gate for explicitly labelled persistent destructive clicks.
 *
 * Inputs must be the freshly verified target's own visible label/description and
 * its observed descendant label. Model reasons, owner-text parsing, package
 * names and resource-id guesses are deliberately not part of this decision.
 * A null classification is not proof that an arbitrary UI action is harmless.
 */
public final class PersistentActionPolicy {
    private PersistentActionPolicy() {}

    public static final class Decision {
        public final boolean allowed;
        public final String reasonCode, detail;
        private Decision(boolean allowed,String reasonCode,String detail) {
            this.allowed=allowed;this.reasonCode=reasonCode;this.detail=detail;
        }
    }

    private static final String[] DESTRUCTIVE_ZH={
        "删除","刪除","清除","清空","清理","擦除","抹掉","移除","重置","重设","重設","格式化","注销","註銷"
    };
    private static final String[] PERSISTENT_ZH={
        "历史","歷史","记录","紀錄","記錄","数据","資料","缓存","緩存","快取",
        "文件","档案","檔案","文档","文檔","照片","图片","圖片","视频","影片",
        "消息","訊息","短信","简讯","簡訊","聊天","联系人","聯絡人","聯繫人",
        "账户","帐户","账号","帐号","帳戶","帳號","用户","用戶","应用","應用",
        "存储","儲存","磁盘","磁碟","设备","設備","手机","手機","设置","設定","設置",
        "所有内容","全部内容","所有內容","全部內容"
    };
    private static final Pattern DESTRUCTIVE_EN=Pattern.compile(
        "\\b(?:delete|remove|clear|erase|wipe|reset|format|deactivate)\\b");
    private static final Pattern PERSISTENT_EN=Pattern.compile(
        "\\b(?:history|records?|data|cache|files?|documents?|photos?|pictures?|videos?|messages?|sms|chats?|conversations?|contacts?|accounts?|users?|apps?|applications?|storage|disks?|devices?|phones?|settings|preferences|all content|all contents)\\b");
    private static final Pattern UNINSTALL_EN=Pattern.compile("\\buninstall\\b");
    private static final Pattern FACTORY_EN=Pattern.compile(
        "\\bfactory\\s+(?:data\\s+)?reset\\b|\\b(?:restore|reset)(?:\\s+to)?\\s+factory(?:\\s+settings)?\\b");

    public static Decision evaluate(String directText,String description,String childText,boolean inputLike) {
        // Clicking an editable field focuses it. Its existing user text is not
        // interpreted as a button command (including a typed search query).
        if(inputLike)return allow("input_focus_not_persistent_command");
        StringBuilder labels=new StringBuilder();
        for(String raw:new String[]{directText,description,childText}) {
            String label=normal(raw);
            if(label.isEmpty()||negativeControl(label))continue;
            if(labels.length()>0)labels.append(' ');
            labels.append(label);
        }
        String text=labels.toString(),compact=text.replace(" ","");
        if(compact.contains("卸载")||compact.contains("卸載")||UNINSTALL_EN.matcher(text).find())
            return reject("persistent_uninstall_unsupported");
        if(compact.contains("恢复出厂")||compact.contains("恢復出廠")||compact.contains("出厂重置")
                ||compact.contains("出廠重置")||FACTORY_EN.matcher(text).find())
            return reject("persistent_factory_reset_unsupported");
        boolean operation=contains(compact,DESTRUCTIVE_ZH)||DESTRUCTIVE_EN.matcher(text).find();
        boolean object=contains(compact,PERSISTENT_ZH)||PERSISTENT_EN.matcher(text).find();
        if(operation&&object)return reject("persistent_destructive_click_unsupported");
        // Bare Clear/Delete, C/AC and current-input editing remain unclassified.
        // The real calculator uses only bare 清除/删除; no package/id heuristic
        // is used to claim that those words are generally safe elsewhere.
        return allow("not_classified_as_explicit_persistent_destruction");
    }

    private static Decision allow(String reason) {return new Decision(true,reason,"");}
    private static Decision reject(String reason) {
        return new Decision(false,reason,"guard:"+reason+"；当前版本不支持自动执行此类持久性删除、清除或重置操作，本次未点击。");
    }
    private static boolean contains(String text,String[] values) {
        for(String value:values)if(text.contains(value))return true;
        return false;
    }
    private static String normal(String value) {
        if(value==null)return "";
        return Normalizer.normalize(value,Normalizer.Form.NFKC).toLowerCase(Locale.ROOT)
                .replaceAll("[\\p{Cf}]","").replaceAll("\\s+"," ").trim();
    }
    private static boolean negativeControl(String text) {
        // Exact visible cancellation controls only; no free-form instruction
        // or owner authorization is inferred from a substring.
        return text.equals("取消删除")||text.equals("取消刪除")||text.equals("不删除")||text.equals("不刪除")
                ||text.equals("不要删除")||text.equals("不要刪除")||text.equals("取消清除")
                ||text.equals("不清除")||text.equals("取消卸载")||text.equals("取消卸載")
                ||text.equals("cancel deletion")||text.equals("cancel delete")||text.equals("don't delete")
                ||text.equals("do not delete")||text.equals("cancel uninstall");
    }
}
