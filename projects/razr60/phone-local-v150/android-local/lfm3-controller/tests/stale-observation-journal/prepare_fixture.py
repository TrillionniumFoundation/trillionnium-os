"""Extract the real rejected-action branches; replace Android/JSON/IO boundaries.

The branch bodies, stale counters, record calls, await ordering and continue
statements are copied byte-for-byte. No device, SDK or real action is invoked.
"""
import hashlib
import json
from pathlib import Path


def prepare(source, output):
    source, output = Path(source), Path(output)
    output.mkdir(parents=True, exist_ok=True)
    controller = (source / "src/org/trillionnium/hepta/local/LocalTaskController.java").read_text(encoding="utf-8")

    def section(start, end):
        if controller.count(start) != 1 or controller.count(end) != 1:
            raise RuntimeError("production stale branch anchors are not unique")
        begin = controller.index(start)
        finish = controller.index(end, begin)
        return controller[begin:finish]

    mismatch = section('                if(!before.id.equals(action.observationId)){',
                       '                if(repeatGuard.rejects(action,before.state)')
    stale = section('                if(outcome.stale&&!outcome.dispatched){',
                    '                if(!outcome.accepted)')
    template = r'''package org.trillionnium.hepta.local;
import java.io.File;
import java.io.IOException;
import java.util.*;

public final class StaleObservationJournalFixture {
    public enum AwaitFailure { NONE, IO, STOP, DEADLINE }
    public static final class Stopped extends Exception { private static final long serialVersionUID=1L; }
    public static final class JSONObject {
        public final Map<String,Object> values=new LinkedHashMap<String,Object>();
        public final String raw;
        public JSONObject(){raw=null;}
        public JSONObject(String raw){this.raw=raw;}
        public JSONObject put(String key,Object value){values.put(key,value);return this;}
        public Object get(String key){return values.get(key);}
    }
    public static final class JSONArray {
        public final List<JSONObject> rows=new ArrayList<JSONObject>();
        public void put(JSONObject value){rows.add(value);}
    }
    public static final class Observation {
        public final String id,packageName,stateHash;
        public final int windowId,rotation;
        public Observation(String id,String packageName,int windowId,int rotation,String stateHash){
            this.id=id;this.packageName=packageName;this.windowId=windowId;this.rotation=rotation;this.stateHash=stateHash;
        }
        public JSONObject toJson(){return new JSONObject().put("observation_id",id).put("package",packageName)
                .put("window_id",windowId).put("rotation",rotation).put("observation_state_sha256",stateHash);}
    }
    public static final class ActionDecision {
        public final String action="click",packageName="com.example.app",observationId;
        public ActionDecision(String observationId){this.observationId=observationId;}
    }
    public static final class ActionOutcome {
        public final boolean accepted,dispatched,stale;
        public final String detail;
        public ActionOutcome(boolean accepted,boolean dispatched,boolean stale,String detail){
            this.accepted=accepted;this.dispatched=dispatched;this.stale=stale;this.detail=detail;
        }
    }
    public final Observation before=new Observation("before","com.example.app",10,0,"before-state");
    public final Observation fresh=new Observation("fresh","com.example.changed",11,1,"fresh-state");
    public Observation observation=before;
    public final Map<String,JSONObject> records=new LinkedHashMap<String,JSONObject>();
    public final List<String> trace=new ArrayList<String>();
    public final JSONArray history=new JSONArray();
    public final String taskId="owned-task",decisionRunId="original-run";
    public final File evidence=new File("fixture-only-no-io");
    public final long deadline=12345;
    public int steps=7,staleRounds,awaitCalls,transitions,fallthrough;
    public Object lastTransition;
    public AwaitFailure failure=AwaitFailure.NONE;
    public String failRecordName;
    private static String answerJson(ActionDecision action){return "{\"action\":\""+action.action
            +"\",\"observation_id\":\""+action.observationId+"\",\"package\":\""+action.packageName+"\"}";}
    private void record(File root,String name,JSONObject value)throws IOException{
        if(root!=evidence)throw new AssertionError("wrong task evidence");
        trace.add("record:"+name);
        if(name.equals(failRecordName))throw new IOException("fixture publication failure");
        if(records.containsKey(name))throw new AssertionError("duplicate record");
        records.put(name,value);
    }
    private void emit(String ignored){trace.add("emit");}
    private Observation awaitObservation(String task,File root,long limit)throws Exception{
        if(!taskId.equals(task)||root!=evidence||limit!=deadline)throw new AssertionError("observation ownership/deadline changed");
        trace.add("await");awaitCalls++;
        if(failure==AwaitFailure.IO)throw new IOException("fixture observation failure");
        if(failure==AwaitFailure.STOP)throw new Stopped();
        if(failure==AwaitFailure.DEADLINE)throw new IllegalStateException("fixture task deadline");
        return fresh;
    }
    private Object observedTransition(int step,Observation old,Observation next){
        if(step!=steps||old!=before||next!=fresh)throw new AssertionError("transition did not receive actual observation");
        trace.add("transition");transitions++;return next.id;
    }
    public void mismatch(ActionDecision action)throws Exception{
        for(int fixtureTurn=0;fixtureTurn<1;fixtureTurn++){
__MISMATCH__
            fallthrough++;
        }
    }
    public void staleOutcome(ActionDecision action,ActionOutcome outcome)throws Exception{
        for(int fixtureTurn=0;fixtureTurn<1;fixtureTurn++){
__STALE__
            fallthrough++;
        }
    }
}
'''
    fixture = template.replace("__MISMATCH__", mismatch).replace("__STALE__", stale)
    path = output / "StaleObservationJournalFixture.java"
    path.write_text(fixture, encoding="utf-8")
    digest = lambda value: hashlib.sha256(value).hexdigest()
    record = {
        "scope": "Exact production mismatch/stale branches; Android observation, JSON rendering and record publication are deterministic fixtures",
        "controller_sha256": digest(controller.encode()),
        "mismatch_branch_sha256": digest(mismatch.encode()),
        "stale_branch_sha256": digest(stale.encode()),
        "fixture_sha256": digest(path.read_bytes()),
        "not_android_runtime": True,
        "not_model_inference": True,
        "not_phone_test": True,
    }
    (output / "EXTRACTION.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return path, record
