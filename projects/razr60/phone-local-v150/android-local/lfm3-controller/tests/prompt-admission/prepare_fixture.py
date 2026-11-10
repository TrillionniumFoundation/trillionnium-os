"""Exercise the exact production projection-selection/pruning decisions.

Android observation/JSON rendering is replaced by deterministic UTF-8 frames.
The admission branch, required-target check, real grammar construction, pruning
order and terminal refusal are copied unchanged from the production controller.
"""
import hashlib
import json
from pathlib import Path


def prepare(source, output):
    source, output = Path(source), Path(output)
    output.mkdir(parents=True, exist_ok=True)
    controller = (source / "src/org/trillionnium/hepta/local/LocalTaskController.java").read_text(encoding="utf-8")
    start = "            ConservativeTokenBudget budget=ConservativeTokenBudget.estimate(SYSTEM,text,config);"
    end = "    /** One JSON object with readable top-level boundaries; the current screen is last. */"
    if controller.count(start) != 1 or controller.count(end) != 1:
        raise RuntimeError("production prompt-admission anchors are not unique")
    decisions = controller[controller.index(start):controller.index(end)]
    fixture = r'''package org.trillionnium.hepta.local;
import java.util.*;
public final class PromptAdmissionFixture {
    private final String SYSTEM;
    public final List<String> attempts=new ArrayList<String>();
    public PromptAdmissionFixture(String system){SYSTEM=system;}
    public static final class PromptFrame {
        public final String text;
        public final Set<String> nodeIds;
        public final ConservativeTokenBudget budget;
        public final DecisionGrammar grammar;
        public final int nodesShown,visibleTextShown;
        PromptFrame(String text,Set<String> ids,Set<String> packages,ConservativeTokenBudget budget,
                    DecisionGrammar grammar,int shown,int observed,int apps,int history,Object catalogue,
                    int fieldsShown,int fieldsObserved,int visibleShown,int visibleObserved,Object events,
                    int historyBytes,Object appSearch,int requiredNodes){
            this.text=text;nodeIds=new LinkedHashSet<String>(ids);this.budget=budget;this.grammar=grammar;
            nodesShown=shown;visibleTextShown=visibleShown;
        }
    }
    private static final class Observation {
        final String id="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",packageName="com.example.fixture";
        final List<String> nodes=new ArrayList<String>();
    }
    private static final class History {int length(){return 2;}}
    private static String repeat(char value,int count){char[] out=new char[count];Arrays.fill(out,value);return new String(out);}
    public PromptFrame project(String owner,int required,int optional,int visible,int mandatoryBytes,
                               LocalRuntimeConfig config,boolean omitRequired)throws Exception{
        Observation observation=new Observation();
        Set<String> requiredIds=new LinkedHashSet<String>();
        for(int i=0;i<required+optional;i++){
            observation.nodes.add("n"+i);if(i<required)requiredIds.add("n"+i);
        }
        int nodeCount=observation.nodes.size(),visibleTextLimit=visible,appCount=1;
        int editableFieldsObserved=0,visibleTextObserved=visible,historyBytes=32;
        Object catalogue=new Object(),events=new Object(),appSearch=new Object();History history=new History();
        while(true){
            attempts.add(visibleTextLimit+"/"+nodeCount);
            Set<String> ids=new LinkedHashSet<String>(),packages=new LinkedHashSet<String>();
            Set<String> clicks=new LinkedHashSet<String>(),edits=new LinkedHashSet<String>();
            Map<String,String> projectedLabels=new LinkedHashMap<String,String>();
            Map<String,ObservedScrollActions> scrolls=new LinkedHashMap<String,ObservedScrollActions>();
            StringBuilder rendered=new StringBuilder("UNTRUSTED_DATA\n").append(repeat('m',mandatoryBytes));
            for(int i=0;i<nodeCount;i++){
                String id="n"+i;if(omitRequired&&i==required-1)continue;
                ids.add(id);projectedLabels.put(id,"target "+i);rendered.append('\n').append(id).append(" target ").append(i);
                if(i<required)clicks.add(id);
            }
            List<String> editableFields=new ArrayList<String>(),visibleText=new ArrayList<String>();
            for(int i=0;i<visibleTextLimit;i++){visibleText.add("optional "+i);rendered.append(repeat('v',200));}
            String text=rendered.append("\nOWNER\n").append(owner).toString();
''' + decisions + "}\n"
    path = output / "PromptAdmissionFixture.java"
    path.write_text(fixture, encoding="utf-8")
    digest = lambda value: hashlib.sha256(value).hexdigest()
    record = {
        "scope": "Exact controller admission branch, required-target/grammar checks, optional reduction order and refusal; Android observation and JSON rendering are deterministic fixtures",
        "controller_sha256": digest(controller.encode()),
        "production_decisions_sha256": digest(decisions.encode()),
        "production_decisions_bytes": len(decisions.encode()),
        "fixture_sha256": digest(path.read_bytes()),
        "not_android_runtime": True,
        "not_model_inference": True,
        "not_phone_test": True,
    }
    (output / "EXTRACTION.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return path, record
