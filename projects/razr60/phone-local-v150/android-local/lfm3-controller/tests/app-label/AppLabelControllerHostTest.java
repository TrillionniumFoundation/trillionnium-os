package org.trillionnium.hepta.local;
import android.graphics.Rect;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;

/** Real prompt/answer/receipt code with synthetic observation and JSON/Rect IO only. */
public final class AppLabelControllerHostTest {
    private static final String OBS="0123456789abcdef0123456789abcdef",CURRENT="org.example.launcher";
    private static int assertions;
    private static void check(boolean yes,String message){assertions++;if(!yes)throw new AssertionError(message);}
    private static PhoneObservation observation(){
        int[] bounds={0,0,1080,2400};
        return new PhoneObservation(OBS,CURRENT,100,1080,2400,0,7,new Rect(0,0,1080,2400),null,"a","b",
                new ObservationState("b",ImeVisibility.HIDDEN),
                ObservedWindowMetadata.observed(bounds,"android.widget.FrameLayout",1,0,bounds,"匿名示例"),
                false,new ArrayList<PhoneObservation.Node>());
    }
    public static void main(String[] args)throws Exception{
        Path out=Paths.get(args[0]);Files.createDirectories(out);
        Map<String,String> installed=new LinkedHashMap<String,String>();
        installed.put(CURRENT,"桌面");installed.put("org.example.target_a","同名");installed.put("org.example.target_b","同名");
        installed.put("org.example.empty","");installed.put("org.example.other","另一个应用");
        installed.put("org.example.long","12345678901234567890123456789012345678901234567😀tail");
        String owner="打开指定应用并保留目标窗口；这是匿名合成任务。";
        AppCatalogueRanker.Page page=new AppCatalogueRanker(installed,owner).search("",0);
        PromptAdmissionFixture.Result frame=PromptAdmissionFixture.build(owner,page,observation(),new JSONArray(),new LocalRuntimeConfig(ModelProfile.GEMMA4_E4B,"npu",8192,4));
        check(frame.grammar.schema.equals(ObservedAppLabels.ACTION_SCHEMA),"actual prompt frame is v4");
        check(frame.grammar.appLabels.labels.size()==5&&!frame.grammar.appLabels.labels.containsKey(CURRENT),"current-app exclusion preserved");
        check(frame.text.contains("\"action_schema\":\""+ObservedAppLabels.ACTION_SCHEMA+"\""),"native-bound prompt explicitly declares schema");
        check(frame.text.contains("[\"org.example.target_a\",\"同名\"]")&&frame.text.contains("[\"org.example.target_b\",\"同名\"]"),"both same-label apps remain in prompt");
        check(frame.text.contains("12345678901234567890123456789012345678901234567…"),"same safe display projection reaches prompt");
        check(frame.text.endsWith("\nOWNER\n"+owner),"original instruction unchanged");
        check(frame.budgetReceipt.get("grammar_schema").equals(frame.grammar.schema),"budget uses instance schema");
        check(frame.budgetReceipt.get("app_label_sha256").equals(frame.grammar.appLabels.sha256),"budget binds exact app projection");
        String firstRaw=null,firstAction=null;
        for(Map.Entry<String,String> pair:frame.grammar.appLabels.labels.entrySet()){
            String raw=new JSONObject().put("reason","遵循当前目标").put("action","open").put("observation_id",OBS)
                    .put("app_label",pair.getValue()).put("package",pair.getKey()).toString();
            ActionDecision action=ActionDecision.parse(raw,frame.grammar.schema);
            ActionPolicy.validateTextDecision(action,CURRENT,frame.grammar.appLabels.labels.keySet(),frame.grammar.targets,frame.grammar.appLabels);
            String serialized=PromptAdmissionFixture.serialize(action);
            ActionDecision recorded=ActionDecision.parse(serialized,frame.grammar.schema);
            check(recorded.appLabel.equals(pair.getValue())&&recorded.packageName.equals(pair.getKey()),"actual answerJson preserves label and original package");
            if(firstRaw==null){firstRaw=raw;firstAction=serialized;}
        }
        JSONObject receipt=PromptAdmissionFixture.grammarReceipt(frame.grammar);
        check(receipt.get("grammar_schema").equals(ObservedAppLabels.ACTION_SCHEMA),"engine emits instance schema");
        check(receipt.getJSONObject("app_label_contract").get("sha256").equals(frame.grammar.appLabels.sha256),"engine emits actual app contract");
        check(Integer.valueOf(5).equals(receipt.getJSONObject("app_label_contract").get("pairs_count")),"engine preserves duplicate-label count by package");
        check(receipt.has("target_label_contract"),"existing node contract retained");
        Files.write(out.resolve("prompt.txt"),frame.text.getBytes(StandardCharsets.UTF_8));
        Files.write(out.resolve("grammar.gbnf"),frame.grammar.text.getBytes(StandardCharsets.UTF_8));
        Files.write(out.resolve("raw.json"),firstRaw.getBytes(StandardCharsets.UTF_8));
        Files.write(out.resolve("action.json"),firstAction.getBytes(StandardCharsets.UTF_8));
        Files.write(out.resolve("app-receipt-fragment.json"),receipt.toString().getBytes(StandardCharsets.UTF_8));
        System.out.println("PASS assertions="+assertions+" exact_prompt_answer_receipt_code=true android_runtime=false phone_tested=false");
    }
}
