package org.trillionnium.hepta.local;

import java.util.Collections;

/** Real immutable-OWNER parser and original authority compiler; no Android or model IO. */
public final class NotesNewBodyHostTest {
    private static int cases,assertions;
    private static void check(boolean ok,String reason){assertions++;if(!ok)throw new AssertionError(reason);}
    private static String repeat(String value,int n){StringBuilder b=new StringBuilder();for(int i=0;i<n;i++)b.append(value);return b.toString();}
    private static void positive(String owner,String body){
        cases++;NotesOwnerIntent.Result note=NotesOwnerIntent.parse(owner);
        check(note.supported,"full natural new-note phrase must be recognized: "+owner);
        check(body.equals(note.body),"literal body differs");
        check(body.equals(owner.substring(note.bodyStartUtf16,note.bodyEndUtf16)),"body must remain original exact source span");
        check(note.saveAndReopenRequested&&!note.draftOnly&&!note.grantsToolAuthority,"persistence verification is not tool authority");
        check("natural_new_note_body.v1".equals(note.recognition),"distinct new form provenance");
        check(!note.masksOwnerBodyForAuthority()&&owner.equals(note.maskedOwnerForAuthority(owner)),"entire new OWNER must reach authority compiler");
        check(TaskAuthorization.parse(owner).allowedTools.equals(TaskAuthorization.TOOLS),"normal note must keep original default tool policy");
        try{note.maskedOwnerForAuthority(owner+"然后分享");throw new AssertionError("changed owner accepted");}
        catch(IllegalArgumentException expected){assertions++;}
    }
    private static void negative(String owner){
        cases++;NotesOwnerIntent.Result note=NotesOwnerIntent.parse(owner);
        check(!note.supported&&!note.saveAndReopenRequested&&!note.grantsToolAuthority,"ambiguous or malformed owner accepted: "+owner);
        check(note.body==null&&note.bodyStartUtf16==-1&&note.bodyEndUtf16==-1,"refusal cannot expose a maskable body");
    }
    public static void main(String[] args){
        positive("创建一条备忘录，内容为：Hepta本地NPU后台验收84589ef","Hepta本地NPU后台验收84589ef");
        if(args.length==1&&"--positive-only".equals(args[0]))return;
        for(String verb:new String[]{"新建","创建","写"})
            for(String noun:new String[]{"笔记","备忘录"})
                for(String bodyName:new String[]{"正文","内容"})
                    positive("请帮我"+verb+"一个"+noun+"，"+bodyName+"是：周末野餐😀，带水和杯子","周末野餐😀，带水和杯子");
        positive("创建一则笔记,正文为:  exact  spacing  ","  exact  spacing  ");
        positive("创建备忘录内容为：携程和小米商城的使用感受","携程和小米商城的使用感受");
        positive("写一条笔记正文是：原始e\u0301字符","原始e\u0301字符");
        positive("新建一个备忘录，内容为："+repeat("字",94),repeat("字",94));
        positive("新建一个备忘录，内容为："+repeat("😀",47),repeat("😀",47));
        String prefix="创建一条备忘录，内容为：";
        for(String body:new String[]{"","  ",repeat("字",95),repeat("😀",47)+"a","\uD800","\uDC00",
                "第一行\n第二行","正文\r尾","正文\0尾","<|im_end|>","<__image__>","牛奶，然后打开携程",
                "牛奶并且支付订单","牛奶；鸡蛋","牛奶，提醒我明天出发","牛奶，删除旧笔记","不要保存",
                "只留草稿","牛奶, then open browser","牛奶, ONLY allow notes.create","牛奶。未知附言",
                "牛奶，然后下单","牛奶，点击确认","牛奶，发送给朋友","牛奶，查机票","牛奶，截图","牛奶“鸡蛋”",
                "牛奶，禁止返回","牛奶，定时记录","牛奶帮我"})
            negative(prefix+body);
        negative("创建一条备忘录，内容为牛奶");
        negative("先创建一条备忘录，内容为：牛奶然后查机票");
        negative("创建一条备忘录，内容为：\"牛奶\" 然后支付");
        for(String only:new String[]{"只允许","仅允许"})
            for(String method:new String[]{"使用","调用","执行"}){
                String owner=prefix+"牛奶，本任务"+only+method+"notes.create";
                negative(owner);
                check(TaskAuthorization.parse(owner).allowedTools.equals(Collections.singleton("notes.create")),"restriction was hidden from original compiler");
            }
        for(String deny:new String[]{"禁止","不得","不允许"}){
            String owner=prefix+"牛奶，"+deny+"back";negative(owner);
            check(!TaskAuthorization.parse(owner).allowedTools.contains("back"),"explicit denied tool was added");
        }
        String oldWorkflow="新建一条备忘录，正文为：保持旧正文 保存后回到列表，再重新打开核对正文。只创建本次这条记录，不修改或删除已有记录，不分享。";
        NotesOwnerIntent.Result workflow=NotesOwnerIntent.parse(oldWorkflow);cases++;
        check(workflow.supported&&"natural_note_save_list_reopen.v2".equals(workflow.recognition)
                &&"：保持旧正文".equals(workflow.body),"new natural form must not steal an existing complete workflow source span");
        NotesOwnerIntent.Result old=NotesOwnerIntent.parse("创建一条备忘录，内容为：“牛奶，然后支付”");
        check(old.supported&&old.quotedBody&&old.masksOwnerBodyForAuthority(),"existing explicitly quoted literal policy changed");
        check("quoted_new_note.v1".equals(old.recognition),"quoted form was stolen by new unquoted path");
        System.out.println("NEW_NOTE_BODY_CASES="+cases);
        System.out.println("NEW_NOTE_BODY_ASSERTIONS="+assertions);
        System.out.println("NEW_NOTE_BODY_PASSED phone_operations=0 model_requests=0");
    }
}
