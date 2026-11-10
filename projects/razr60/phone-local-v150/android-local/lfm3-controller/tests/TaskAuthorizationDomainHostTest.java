import java.util.Arrays;
import java.util.Set;
import java.util.TreeSet;
import org.trillionnium.hepta.local.TaskAuthorization;

/** Real OWNER parser regression: no model, phone, Android fixture or IO. */
public final class TaskAuthorizationDomainHostTest {
    private static int passed;
    private static void check(boolean ok,String message){if(!ok)throw new AssertionError(message);}
    private static void ordinary(String owner){
        TaskAuthorization parsed=TaskAuthorization.parse(owner);
        check(!parsed.requireFindAppBeforeOpen,"content was compiled as installed-app lookup: "+owner);
        check(parsed.findQuery==null,"ordinary content acquired a lookup query");
        check(parsed.allowedTools.equals(TaskAuthorization.TOOLS),"ordinary content changed tool permissions");
        TaskAuthorization.Frame frame=parsed.bind("11111111111111111111111111111111").frame();
        check(frame.allows("click")&&frame.allows("type")&&frame.allows("scroll"),"content acquired a hidden lookup gate");
        passed++;
    }
    private static void lookup(String owner,String query){
        TaskAuthorization parsed=TaskAuthorization.parse(owner);
        check(parsed.requireFindAppBeforeOpen&&query.equals(parsed.findQuery),"explicit app query not preserved: "+owner);
        TaskAuthorization.Frame frame=parsed.bind("22222222222222222222222222222222").frame();
        check(frame.allows("find_app")&&!frame.allows("click")&&!frame.allows("type")&&!frame.successAllowed(),
                "explicit app prerequisite lost its enforcement");
        passed++;
    }
    private static void refused(String owner){
        try{TaskAuthorization.parse(owner);}catch(TaskAuthorization.Violation expected){passed++;return;}
        throw new AssertionError("explicit unsupported/conflicting instruction was accepted: "+owner);
    }
    public static void main(String[] args){
        ordinary("先在携程查找明天北京到上海的机票，然后打开最便宜的航班查看详情。");
        ordinary("先查找蓝牙耳机，再打开价格最低的商品。");
        ordinary("先在淘宝应用里查找蓝牙耳机，再打开价格最低的商品。");
        ordinary("先在备忘录查找客户，再打开相关文档。");
        ordinary("先查找关于应用的文章，再打开详情。");
        ordinary("在备忘录写下“先查找客户，再打开文档”并保存。");
        ordinary("在备忘录写下‘先查找时钟应用，再打开它’并保存。");
        ordinary("在备忘录写下\"先调用find_app搜索时钟，再打开它\"并保存。");
        ordinary("在备忘录写下“先查找手机上安装的时钟应用，再打开它”并保存。");
        ordinary("打开携程，查找明天北京到上海的机票，查看最便宜的航班。");
        lookup("先只读查找手机上安装的时钟应用，再打开它并停留在主页面。","时钟");
        lookup("先查找手机上安装的时钟，再打开它。","时钟");
        lookup("先查找“时钟”应用，再打开它。","时钟");
        lookup("先查找\"时钟\"应用，再打开它。","时钟");
        lookup("先查找“时钟”APP，然后打开它。","时钟");
        lookup("请先使用本机应用查找工具find_app搜索‘计算器’，再从查找结果打开计算器。","计算器");
        lookup("在备忘录输入“客户”，然后先查找‘时钟’应用，再打开它。","时钟");
        refused("先查找手机上安装的时钟应用并打开它。");
        refused("先查找时钟应用并打开它。");
        refused("先查找时钟应用，再打开它；先查找计算器应用，再打开它。");
        refused("只允许查找和结束，先查找时钟应用，再打开它。");
        refused("只允许打开和结束，可以点击。");
        refused("禁止点击，但是允许点击。");
        TaskAuthorization clock=TaskAuthorization.parse("先只读查找手机上安装的时钟应用，再打开它并停留在主页面；只查找、打开和结束，不点击、不输入，不新建、修改、启停或删除任何闹钟、计时器或秒表。若打开后不是主页面，停止并说明。");
        Set<String> expected=new TreeSet<String>(Arrays.asList("find_app","open","done"));
        check(clock.allowedTools.equals(expected)&&clock.requireFindAppBeforeOpen&&"时钟".equals(clock.findQuery),
                "original constrained Clock contract changed");passed++;
        check("hepta.owner-tool-clauses.zh.v2".equals(TaskAuthorization.PARSER),"changed semantics need a new parser identity");passed++;
        System.out.println("TaskAuthorizationDomainHostTest: "+passed+" cases passed; real parser, no phone/model operations");
    }
}
