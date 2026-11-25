package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.trillionnium.hepta.background.ProfileTarget;

/** A literal OWNER app designation, never a business contract or authorization.
 * Saved instances, installed identities and task tools are checked by the caller.
 * Ambiguous target designations require the existing manual target choice.
 */
final class OwnerExplicitAppRoute {
    static final String RECOGNITION="owner_explicit_saved_app_route.v1";
    // Same byte bound as TaskAuthorization.validOwner and NativeAppGoal.valid.
    private static final int MAX_OWNER_BYTES=1600;
    private static final String ALIASES="携程旅行|携程|小米商城|Moto ?笔记|备忘录";
    private static final Pattern TARGET=Pattern.compile(
            "\\A\\s*(?:(?:请(?:你)?|麻烦(?:你)?)(?:帮我)?|帮我)?\\s*"
            +"(在|用|打开|启动|进入)\\s*("+ALIASES+")"
            +"(?:\\s*(?:App|APP|app|应用))?(?:中|里|上)?\\s*([\\s\\S]*)\\z");
    private static final Pattern MENTION=Pattern.compile(ALIASES);
    private static final Pattern COMMAND=Pattern.compile(
            "\\A(?:查询|查找|查|搜索|搜|看看|查看|浏览|显示|打开|进入|找到|找"
            +"|记录|记|新建|创建|保存|写|添加|编辑|修改|设置|滚动|向上|向下|返回|购买|买|下单)");
    private static final String TARGET_VERB="(?:打开|启动|进入|使用|切换到|改用|换用|选择|在|用)";
    private static final Pattern NEGATED_TARGET=Pattern.compile(
            "(?:不要|不得|不允许|不必|不用|不能|不想|不是|不|别|勿|无需|无须|禁止)"
            +"\\s*(?:(?:再|去|直接|自动|真的|继续)\\s*)*(?:"+TARGET_VERB+"\\s*)?("+ALIASES+")");
    // Only a conditional designation of an App is refused. Conditions or tool
    // denials elsewhere are not deleted, reinterpreted or granted by routing.
    private static final Pattern CONDITIONAL_TARGET=Pattern.compile(
            "(?:如果|假如|要是|除非|否则|只有|仅当|若|是否|能否|也许)"
            +"[^，,。；;！？!?]{0,24}?(?:"+TARGET_VERB+"\\s*)?("+ALIASES+")");

    static String packageName(String owner){
        String plain=unquoted(owner);
        if(plain==null||NEGATED_TARGET.matcher(plain).find()||CONDITIONAL_TARGET.matcher(plain).find())return null;
        Matcher target=TARGET.matcher(plain);
        if(!target.matches())return null;
        String pkg=packageFor(target.group(2));
        String tail=target.group(3).trim().replaceFirst("\\A[，,：:]\\s*","");
        tail=tail.replaceFirst("\\A(?:然后|并|再|请)\\s*","");
        boolean direct="打开".equals(target.group(1))||"启动".equals(target.group(1))||"进入".equals(target.group(1));
        if(!(direct&&tail.isEmpty())&&!COMMAND.matcher(tail).find())return null;
        Set<String> mentioned=new LinkedHashSet<String>();
        Matcher mentions=MENTION.matcher(plain);
        while(mentions.find())mentioned.add(packageFor(mentions.group()));
        if(mentioned.size()!=1||!mentioned.contains(pkg))return null;
        return protectedBusinessPrefix(owner,plain,pkg)?null:pkg;
    }

    /** A supported NativeAppGoal followed by extra clauses must not silently
     * lose its read-only/preview ceiling by becoming a generic task. Prefixes
     * are examined only to REFUSE this fallback; no truncated owner or goal is
     * returned, scheduled, authorized or used as a completion contract.
     */
    private static boolean protectedBusinessPrefix(String owner,String plain,String pkg){
        // At most 1599 candidates under the existing 1600-byte OWNER/goal bound.
        // Test every complete, non-data prefix rather than guessing connectors.
        // A trimmed prefix can only refuse fallback; it never leaves this method.
        int previousLength=0;
        for(int end=1;end<owner.length();end++){
            char last=owner.charAt(end-1);
            if(Character.isHighSurrogate(last)||plain.charAt(end-1)!=last)continue;
            String candidate=owner.substring(0,end).trim();
            if(candidate.length()<=previousLength)continue;
            previousLength=candidate.length();
            if(NativeAppGoal.parse(candidate,pkg)!=null)return true;
        }
        return false;
    }

    private static String packageFor(String alias){
        if("携程".equals(alias)||"携程旅行".equals(alias))return ProfileTarget.CTRIP;
        if("小米商城".equals(alias))return ProfileTarget.XIAOMI;
        if("备忘录".equals(alias)||"Moto笔记".equals(alias)||"Moto 笔记".equals(alias))
            return BackgroundAutoTargetPreferences.NOTES;
        throw new IllegalArgumentException("unknown literal app alias");
    }

    /** Preserve positions and token boundaries; no quoted text can name a target.
     * Nested, unmatched or escaped quotes decline this fallback, never strip into
     * a different apparent instruction. The original OWNER itself is not changed.
     */
    private static String unquoted(String owner){
        if(owner==null||owner.isEmpty()||owner.getBytes(StandardCharsets.UTF_8).length>MAX_OWNER_BYTES)return null;
        StringBuilder plain=new StringBuilder(owner.length());char closing=0;
        for(int i=0;i<owner.length();i++){
            char c=owner.charAt(i);
            if(c=='\\'||c=='\n'||c=='\r'||c==0)return null;
            char expected=closingFor(c);
            if(closing!=0){
                if(c==closing)closing=0;
                else if(expected!=0||isClosing(c))return null;
                plain.append(' ');
            }else if(expected!=0){
                closing=expected;plain.append(' ');
            }else if(isClosing(c))return null;
            else plain.append(c);
        }
        return closing==0?plain.toString():null;
    }
    private static char closingFor(char c){
        if(c=='"'||c=='\''||c=='\u0060')return c;
        if(c=='“')return '”';if(c=='‘')return '’';
        if(c=='「')return '」';if(c=='『')return '』';
        return 0;
    }
    private static boolean isClosing(char c){return c=='”'||c=='’'||c=='」'||c=='』';}
    private OwnerExplicitAppRoute(){}
}
