package org.trillionnium.hepta.local;

import java.io.IOException;
import org.trillionnium.hepta.local.StaleObservationJournalFixture.ActionDecision;
import org.trillionnium.hepta.local.StaleObservationJournalFixture.ActionOutcome;
import org.trillionnium.hepta.local.StaleObservationJournalFixture.AwaitFailure;
import org.trillionnium.hepta.local.StaleObservationJournalFixture.JSONObject;

/** Real production branch bodies; deterministic observation/publication boundaries. */
public final class StaleObservationJournalHostTest {
    private static int cases;
    private static final String ACTION="step-07-action.json",AFTER="step-07-after.json";
    private static void check(boolean value,String message){if(!value)throw new AssertionError(message);}
    private static ActionOutcome stale(){return new ActionOutcome(false,false,true,"stale:fixture fresh screen changed");}
    private static ActionDecision decision(boolean mismatch){return new ActionDecision(mismatch?"wrong-original-id":"before");}
    private static void seedExistingAction(StaleObservationJournalFixture f){
        f.records.put(ACTION,new JSONObject().put("accepted",false).put("dispatched",false).put("stale",true));
    }
    private static void execute(StaleObservationJournalFixture f,boolean mismatch)throws Exception{
        if(mismatch)f.mismatch(decision(true));else f.staleOutcome(decision(false),stale());
    }
    private static void freshAfter(StaleObservationJournalFixture f){
        JSONObject after=f.records.get(AFTER);check(after!=null,"fresh after record must exist");
        check("fresh".equals(after.get("observation_id"))&&!"before".equals(after.get("observation_id")),"never copy before as after");
        check("com.example.changed".equals(after.get("package"))&&Integer.valueOf(11).equals(after.get("window_id"))
                &&Integer.valueOf(1).equals(after.get("rotation"))&&"fresh-state".equals(after.get("observation_state_sha256")),
                "after binds every returned observation field");
        check(f.trace.indexOf("await")<f.trace.indexOf("record:"+AFTER)
                &&f.trace.indexOf("record:"+AFTER)<f.trace.indexOf("transition"),"await then record then existing transition");
        check(f.awaitCalls==1&&f.transitions==1&&f.fallthrough==0&&f.staleRounds==1,"one fresh observation, original continue, no action fallthrough");
        check(f.history.rows.size()==1,"original rejection history is retained");
    }
    private static void observationFailure(boolean mismatch,AwaitFailure failure)throws Exception{
        StaleObservationJournalFixture f=new StaleObservationJournalFixture();f.failure=failure;
        if(!mismatch)seedExistingAction(f);
        boolean threw=false;
        try{execute(f,mismatch);}
        catch(Exception error){
            threw=true;
            check((failure==AwaitFailure.IO&&error instanceof IOException)
                    ||(failure==AwaitFailure.STOP&&error instanceof StaleObservationJournalFixture.Stopped)
                    ||(failure==AwaitFailure.DEADLINE&&error instanceof IllegalStateException),"original await failure propagates");
        }
        check(threw&&f.awaitCalls==1&&!f.records.containsKey(AFTER)&&f.observation==f.before,"failed await cannot invent after");
        check(f.records.containsKey(ACTION)&&f.transitions==0&&f.fallthrough==0,"rejected action remains, no transition/automatic dispatch");cases++;
    }
    private static void exhausted(boolean mismatch)throws Exception{
        StaleObservationJournalFixture f=new StaleObservationJournalFixture();f.staleRounds=2;
        if(!mismatch)seedExistingAction(f);
        boolean threw=false;try{execute(f,mismatch);}catch(IllegalStateException expected){threw=true;}
        check(threw&&f.staleRounds==3&&f.awaitCalls==0&&!f.records.containsKey(AFTER),"existing consecutive stale limit is unchanged");
        check(f.records.containsKey(ACTION)&&f.transitions==0&&f.fallthrough==0&&f.history.rows.isEmpty(),"exhaustion never fabricates observation or dispatch");cases++;
    }
    private static void publicationFailure(boolean mismatch)throws Exception{
        StaleObservationJournalFixture f=new StaleObservationJournalFixture();f.failRecordName=AFTER;
        if(!mismatch)seedExistingAction(f);
        boolean threw=false;try{execute(f,mismatch);}catch(IOException expected){threw=true;}
        check(threw&&f.observation==f.fresh&&f.awaitCalls==1&&!f.records.containsKey(AFTER),"failed publication does not claim a stored after");
        check(f.transitions==0&&f.fallthrough==0,"publication failure cannot continue or redispatch");cases++;
    }
    public static void main(String[] ignored)throws Exception{
        StaleObservationJournalFixture mismatch=new StaleObservationJournalFixture();execute(mismatch,true);freshAfter(mismatch);
        JSONObject rejected=mismatch.records.get(ACTION);
        check(rejected!=null&&Boolean.FALSE.equals(rejected.get("accepted"))&&Boolean.FALSE.equals(rejected.get("dispatched"))
                &&Boolean.TRUE.equals(rejected.get("stale"))&&Boolean.TRUE.equals(rejected.get("model_issued")),"explicit rejected, undispatched model action");
        check("original-run".equals(rejected.get("model_run_id"))&&"observation_id mismatch; nothing dispatched".equals(rejected.get("detail")),"original run and rejection reason retained");
        check(((JSONObject)rejected.get("action")).raw.contains("\"observation_id\":\"wrong-original-id\""),"wrong original action ID is not rewritten");
        check(mismatch.records.size()==2,"one rejection and one real observation record");cases++;

        StaleObservationJournalFixture outcome=new StaleObservationJournalFixture();seedExistingAction(outcome);
        JSONObject existing=outcome.records.get(ACTION);execute(outcome,false);freshAfter(outcome);
        check(outcome.records.get(ACTION)==existing&&outcome.records.size()==2,"existing dispatch rejection is not overwritten");cases++;

        for(AwaitFailure failure:new AwaitFailure[]{AwaitFailure.IO,AwaitFailure.STOP,AwaitFailure.DEADLINE})
            for(boolean wrongId:new boolean[]{true,false})observationFailure(wrongId,failure);
        exhausted(true);exhausted(false);

        StaleObservationJournalFixture matching=new StaleObservationJournalFixture();matching.mismatch(decision(false));
        check(matching.records.isEmpty()&&matching.awaitCalls==0&&matching.staleRounds==0&&matching.fallthrough==1,"matching ID branch remains unaffected");cases++;
        for(ActionOutcome normal:new ActionOutcome[]{new ActionOutcome(true,true,false,"accepted"),new ActionOutcome(true,true,true,"already dispatched")}){
            StaleObservationJournalFixture f=new StaleObservationJournalFixture();f.staleOutcome(decision(false),normal);
            check(f.records.isEmpty()&&f.awaitCalls==0&&f.staleRounds==0&&f.fallthrough==1,"non-rejected outcome branch remains unaffected");cases++;
        }
        publicationFailure(true);publicationFailure(false);
        System.out.println("PASS cases="+cases+" production rejected-action journal branches; observation/JSON/IO fixtures=true; no Android/SDK/phone");
    }
}
