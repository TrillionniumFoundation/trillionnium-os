package org.trillionnium.hepta.local;
import android.graphics.Rect;
import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

/** Actual Node class is extracted unchanged; Rect and exploratory XML binding are host-only. */
public final class NativeSelectionFactsHostTest {
    private static int assertions;
    private static final List<String> names=new ArrayList<String>();
    private NativeSelectionFactsHostTest() {}
    private static void check(boolean b,String why){assertions++;if(!b)throw new AssertionError(why);}
    private static void run(String name,Runnable test){check(!names.contains(name),"unique case");test.run();names.add(name);}
    private static PhoneObservation.Node node(Boolean selected,Boolean checkable,Boolean checked){
        return new PhoneObservation.Node("n0","ctrip.android.view","android.widget.TextView","test:id/choice","单程","",
                new Rect(0,0,20,20),false,false,false,true,false,false,ObservedChildText.notApplicable(),
                ObservedScrollActions.UNKNOWN,ObservedImeEnter.UNKNOWN,null,false,null,"0/0","android.widget.LinearLayout",
                selected,checkable,checked);
    }
    private static PhoneObservation.Node legacy(){
        return new PhoneObservation.Node("n0","ctrip.android.view","android.widget.TextView","test:id/choice","单程","",
                new Rect(0,0,20,20),false,false,false,true,false,false,ObservedChildText.notApplicable(),
                ObservedScrollActions.UNKNOWN,ObservedImeEnter.UNKNOWN,null,false,null,"0/0","android.widget.LinearLayout");
    }
    private static JSONObject facts(PhoneObservation.Node n){return n.json().getJSONObject("native_selection_state");}
    public static void main(String[] args)throws Exception{
        final JSONObject fixture=new JSONObject(new String(Files.readAllBytes(Paths.get(args[0])),StandardCharsets.UTF_8));
        run("legacy_unknown_is_not_observed_false",()->{
            PhoneObservation.Node n=legacy();
            check(!n.selectionStateObserved&&n.selected==null&&n.checkable==null&&n.checked==null,"unknown tuple");
            check(!n.json().has("native_selection_state"),"legacy JSON unchanged");
        });
        run("all_false_are_observed_explicit_values",()->{
            PhoneObservation.Node n=node(false,false,false);JSONObject f=facts(n);
            check(n.selectionStateObserved&&f.getBoolean("observed"),"known observation");
            check(!f.getBoolean("selected")&&!f.getBoolean("checkable")&&!f.getBoolean("checked"),"false preserved");
        });
        run("selected_true_is_preserved",()->check(facts(node(true,false,false)).getBoolean("selected"),"selected"));
        run("checked_true_is_separate_from_selected",()->{
            JSONObject f=facts(node(false,true,true));
            check(!f.getBoolean("selected")&&f.getBoolean("checked")&&f.getBoolean("checkable"),"distinct facts");
        });
        run("partial_unknown_tuples_are_rejected",()->{
            Boolean[][] rows={{null,false,false},{false,null,false},{false,false,null},{null,null,false},{null,false,null},{false,null,null}};
            for(Boolean[] v:rows){boolean rejected=false;try{node(v[0],v[1],v[2]);}catch(IllegalArgumentException expected){rejected=true;}check(rejected,"mixed known/unknown");}
        });
        run("selection_facts_do_not_create_action_capability",()->{
            PhoneObservation.Node n=node(true,true,true);JSONObject json=n.json(),f=facts(n);
            check(!n.clickable&&!n.editable&&!n.submitAvailable,"no flags granted");
            check(!json.has("clickable")&&!json.has("editable")&&!f.getBoolean("grants_action_capability"),"no JSON grants");
            check("same_bounded_accessibility_traversal".equals(f.getString("source")),"explicit source");
        });
        run("changing_only_selection_changes_serialized_facts",()->{
            check(!node(true,false,false).json().toString().equals(node(false,false,false).json().toString()),"state affects evidence");
        });
        run("fixture_is_root_exploration_not_agent_evidence",()->{
            check("hepta.root-exploration-selection-fixture.v1".equals(fixture.getString("schema")),"schema");
            check(!fixture.getBoolean("hepta_task_authority")&&!fixture.getBoolean("node_refs_authentic"),"no live proof");
            check("e7f34d9e8225de7792ccd43481e83c6eef809496262b65018e2bfa4b629fe1f6".equals(fixture.getString("xml_sha256")),"original XML");
        });
        run("actual_ctrip_single_trip_flag_retained",()->{
            JSONArray rows=fixture.getJSONArray("trip_tabs");int selected=0;
            check(rows.length()==3,"three actual modes");
            for(int i=0;i<rows.length();i++){
                JSONObject row=rows.getJSONObject(i);String label=row.getString("content_desc");
                PhoneObservation.Node n=node(row.getBoolean("selected"),row.getBoolean("checkable"),row.getBoolean("checked"));
                boolean actual=facts(n).getBoolean("selected");
                check(actual==row.getBoolean("selected"),"raw flag preserved");
                if(actual){selected++;check("单程".equals(label),"single selected");}
                else check("往返".equals(label)||"多程".equals(label),"other mode explicit false");
            }
            check(selected==1,"one selected mode");
        });
        run("actual_passengers_remain_text_facts_not_selection_inference",()->{
            JSONObject p=fixture.getJSONObject("passengers");
            check("1成人".equals(p.getString("tv_adult_count")),"adult");
            check("0儿童".equals(p.getString("tv_child_count"))&&"0婴儿".equals(p.getString("tv_baby_count")),"no extra passengers");
        });
        JSONObject result=new JSONObject().put("schema","hepta.native-selection-facts-host.v1").put("all_pass",true)
                .put("cases",names.size()).put("assertions",assertions).put("case_names",new JSONArray(names))
                .put("android_service_executed",false).put("live_node_refs",false);
        System.out.println(result.toString());
    }
}
