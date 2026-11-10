package org.trillionnium.hepta.local;

import java.util.Arrays;

/** Tests actual production selection/pruning decisions, with rendered-text IO fixtures. */
public final class PromptAdmissionHostTest {
    private static int cases;
    private static final String OWNER="完整 OWNER <task>：保留原指令，不改目标。";
    private static String repeat(char value,int count){char[] out=new char[count];Arrays.fill(out,value);return new String(out);}
    private static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
    private static LocalRuntimeConfig config(ModelProfile profile,int context){return new LocalRuntimeConfig(profile,"npu",context,4);}
    private static void refused(String system,String owner,int required,int optional,int visible,int mandatory,
                                LocalRuntimeConfig config,String reason)throws Exception{
        boolean rejected=false;
        try{new PromptAdmissionFixture(system).project(owner,required,optional,visible,mandatory,config,false);}
        catch(IllegalStateException expected){rejected=true;}
        check(rejected,reason);cases++;
    }
    public static void main(String[] ignored)throws Exception{
        LocalRuntimeConfig gemma=config(ModelProfile.GEMMA4_E4B,4096);
        PromptAdmissionFixture exact=new PromptAdmissionFixture(repeat('s',3593));
        PromptAdmissionFixture.PromptFrame frame=exact.project(OWNER,3,2,2,3000,gemma,false);
        check(frame.budget.admitted&&frame.budget.totalContextUpper>4096,"minimal complete frame reaches exact native guard");
        check(exact.attempts.equals(Arrays.asList("2/5","1/5","0/5","0/4","0/3")),"original optional pruning order preserved");
        check(frame.nodesShown==3&&frame.visibleTextShown==0&&frame.nodeIds.containsAll(Arrays.asList("n0","n1","n2")),"all required targets survive reduction");
        check(frame.grammar.targets.labels.keySet().equals(frame.nodeIds)&&frame.text.endsWith("\nOWNER\n"+OWNER),"unchanged OWNER and grammar-bound selected targets");cases++;

        PromptAdmissionFixture small=new PromptAdmissionFixture("system");
        frame=small.project(OWNER,3,2,2,20,gemma,false);
        check(small.attempts.size()==1&&frame.nodesShown==5&&frame.visibleTextShown==2,"within-target optional context is retained");cases++;

        PromptAdmissionFixture partial=new PromptAdmissionFixture(repeat('s',3593));
        frame=partial.project(OWNER,3,2,2,2100,gemma,false);
        check(partial.attempts.equals(Arrays.asList("2/5","1/5"))&&frame.nodesShown==5&&frame.visibleTextShown==1,
                "reduction stops as soon as original sizing target is met");cases++;

        PromptAdmissionFixture bytes=new PromptAdmissionFixture("system");
        frame=bytes.project(OWNER,3,2,4,65000,gemma,false);
        check(frame.budget.admitted&&frame.budget.promptBytesUpper<=65536&&frame.nodesShown==3&&frame.visibleTextShown==0,
                "byte overflow can reduce optional context but preserves complete required frame");cases++;

        refused("system",OWNER,3,2,2,65536,gemma,"required frame byte overflow remains refused");
        refused(repeat('s',65537),OWNER,3,2,2,10,gemma,"system byte overflow remains refused");
        refused("system",repeat('o',65537),3,2,2,10,gemma,"OWNER is not truncated to meet byte limit");
        refused(repeat('s',3593),OWNER,3,2,2,3000,config(ModelProfile.LFM3,4096),"LFM3 proven-bound refusal unchanged");

        boolean missing=false;
        try{new PromptAdmissionFixture(repeat('s',3593)).project(OWNER,3,2,2,3000,gemma,true);}
        catch(IllegalStateException expected){missing=true;}
        check(missing,"heuristic fallback never bypasses complete required-domain check");cases++;

        PromptAdmissionFixture noOptional=new PromptAdmissionFixture(repeat('s',3593));
        frame=noOptional.project(OWNER,3,0,0,3000,gemma,false);
        check(noOptional.attempts.size()==1&&frame.nodesShown==3&&frame.budget.admitted,"complete minimal frame is admitted once");cases++;

        System.out.println("PASS cases="+cases+" actual projection-selection decisions; rendering fixture=true; no tokenizer/SDK/Android/phone");
    }
}
