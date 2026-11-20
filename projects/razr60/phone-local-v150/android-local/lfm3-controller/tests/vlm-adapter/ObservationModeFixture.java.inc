package org.trillionnium.hepta.local;

import java.io.File;
import org.json.JSONObject;

/** Exact production observation branch. Parsing/dispatch counters are host-only spies. */
public final class ObservationModeHostTest {
    private static int parseCalls,dispatchCalls,records;
    private static JSONObject saved;
    private static final class Frame {final String id="11111111111111111111111111111111";}
    private static final class ModelAnswer {
        final String text,runId="22222222222222222222222222222222";ModelAnswer(String text){this.text=text;}
    }
    private static void record(File directory,String leaf,JSONObject object){
        if(!"visual-observation-only.json".equals(leaf))throw new AssertionError("wrong evidence name");
        records++;saved=object;
    }
    private static final class ParserReached extends RuntimeException {
        private static final long serialVersionUID=1L;
    }
    private static void probe(final boolean tools,String raw)throws Exception{
        LocalInference inference=new LocalInference(){
            public LocalRuntimeConfig configuration(){return new LocalRuntimeConfig(ModelProfile.GUI_OWL_4B,"npu",8192,4,!tools);}
            public boolean modelOutputDispatchAllowed(){return tools;}
            public Handle generate(String p,String s,File f,DecisionGrammar g,int n,long t,Callback c){throw new AssertionError("unexpected model run");}
        };
        String taskId="33333333333333333333333333333333",finalStatus="",summary="";
        File evidence=null;Frame before=new Frame();ModelAnswer answer=new ModelAnswer(raw);
        taskSteps: while(true){
/* EXACT_OBSERVE_GATE */
            parseCalls++;throw new ParserReached();
        }
        if(!"partial".equals(finalStatus)||!summary.contains("未执行模型工具调用"))
            throw new AssertionError("observation-only terminal was changed");
    }
    public static void main(String[] args)throws Exception{
        for(String raw:new String[]{"not JSON", "{\"action\":\"purchase\"}", "{\"action\":\"home\"}", "{}", "", null}){
            parseCalls=dispatchCalls=records=0;saved=null;probe(false,raw);
            if(parseCalls!=0||dispatchCalls!=0||records!=1||saved==null
                    ||saved.getBoolean("model_output_dispatched")||saved.getBoolean("business_completion_verified")
                    ||saved.getBoolean("automatic_resume"))throw new AssertionError("observation reached parsing or dispatch");
        }
        parseCalls=records=0;
        try{probe(true,"not JSON");throw new AssertionError("tools path did not reach its parser");}
        catch(ParserReached expected){if(parseCalls!=1||records!=0)throw new AssertionError("observation gate contaminated tools path");}
        System.out.println("PASS 7 exact production observation-gate cases; parser/dispatch are host spies");
    }
}
