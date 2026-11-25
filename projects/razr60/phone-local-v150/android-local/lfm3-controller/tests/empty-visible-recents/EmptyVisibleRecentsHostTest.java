package org.trillionnium.hepta.background;

import java.lang.reflect.Method;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONArray;
import org.json.JSONObject;

/** Real production parsers; portable synthetic rows plus optional private original files.
 * No Android, Binder, display creation, cleanup, or action authority is exercised. */
public final class EmptyVisibleRecentsHostTest {
    private static final ProfileTarget TARGET=ProfileBrokerHostTest.target(10,1010367);
    private static final String MAIN="org.trillionnium.hepta.local/.MainActivity";
    private static final String MAIN_FULL="org.trillionnium.hepta.local/org.trillionnium.hepta.local.MainActivity";
    private static final JSONArray CASES=new JSONArray(), REFUSALS=new JSONArray();
    private static int assertions;
    private static PublicPersonalNotesAbsenceRecovery.Request NOTES;
    private interface Work {void run()throws Exception;}
    private static void yes(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
    private static void pass(String name,Work work)throws Exception{work.run();CASES.put(name);}
    private static String replace(String raw,String old,String value){
        int start=raw.indexOf(old);yes(start>=0&&start==raw.lastIndexOf(old),"fixture seam not unique: "+old);
        return raw.substring(0,start)+value+raw.substring(start+old.length());
    }
    private static String header(){
        return "ACTIVITY MANAGER RECENT TASKS (dumpsys activity recents)\n"
            +"mRecentsUid=10100\nmRecentsComponent=ComponentInfo{com.example.launcher/com.example.launcher.Recents}\n"
            +"mFreezeTaskListReordering=false\nmFreezeTaskListReorderingPendingTimeout=false\n"
            +"mHiddenTasks=[Task{aaa77 #777 type=standard A=10481:org.trillionnium.hepta.local}, "
            +"Task{aaa78 #778 type=standard A=10101:com.example.hidden}]\n  Recent tasks:\n";
    }
    private static String homeRow(int index,int id,int display){
        return "  * Recent #"+index+": Task{ab"+id+" #"+id+" type=home A=10100:com.example.launcher}\n"
            +"    userId=0 effectiveUid=u0a100 mCallingUid=0\n"
            +"    affinity=10100:com.example.launcher\n"
            +"    intent={act=android.intent.action.MAIN cat=[android.intent.category.HOME] flg=0x10000100 cmp=com.example.launcher/.Home}\n"
            +"    mActivityComponent=com.example.launcher/.Home\n"
            +"    autoRemoveRecents=false isPersistable=true activityType=2\n"
            +"    Activities=[]\n    taskId="+id+" rootTaskId="+id+"\n"
            +"    lastActiveTime=100 (inactive for 0s)\n    lastDisplayId="+display+"\n";
    }
    private static String controllerRow(int index,int id,int display){
        return "  * Recent #"+index+": Task{be"+id+" #"+id+" type=standard A=10481:org.trillionnium.hepta.local}\n"
            +"    userId=0 effectiveUid=u0a481 mCallingUid=2000\n"
            +"    affinity=10481:org.trillionnium.hepta.local\n"
            +"    intent={act=android.intent.action.MAIN cat=[android.intent.category.LAUNCHER] flg=0x18800000 cmp="+MAIN+"}\n"
            +"    mActivityComponent="+MAIN+"\n"
            +"    autoRemoveRecents=true isPersistable=false activityType=1\n"
            +"    Activities=[ActivityRecord{ca"+id+" u0 "+MAIN+" t"+id+"}]\n"
            +"    taskId="+id+" rootTaskId="+id+"\n"
            +"    lastActiveTime=200 (inactive for 0s)\n    lastDisplayId="+display+"\n";
    }
    private static String home(){return header()+homeRow(0,101,0)+homeRow(1,102,1)+homeRow(2,103,0);}
    private static String controller(){return header()+controllerRow(0,900,7)+homeRow(1,101,0)+homeRow(2,102,1)+homeRow(3,103,0);}
    private static String visible(){
        return home()+"  Visible recent tasks (most recent first):\n"
            +"  * RecentTaskInfo #0:\n    id=101 userId=0 hasTask=true lastActiveTime=100\n"
            +"    isExcluded=false autoRemoveRecents=false\n"
            +"    baseIntent=Intent {flg=0x10000100 cmp=com.example.launcher/.Home}\n"
            +"    lastDisplayId=0\n";
    }
    private static PublicProfileRecentHistory.Snapshot history(String raw)throws Exception{
        return PublicProfileRecentHistory.absence(raw,TARGET);
    }
    private static PublicPersonalNotesHistory.Snapshot notes(String raw)throws Exception{
        return PublicPersonalNotesHistory.absence(raw,NOTES);
    }
    private static Object retirement(String raw)throws Exception{
        Class<?> type=Class.forName("org.trillionnium.hepta.background.PublicPersonalNotesRetirement$History");
        Constructor<?> constructor=type.getDeclaredConstructor(String.class);constructor.setAccessible(true);
        try{return constructor.newInstance(raw);}
        catch(InvocationTargetException wrapped){Throwable cause=wrapped.getCause();if(cause instanceof Exception)throw (Exception)cause;throw (Error)cause;}
    }
    private static String retirementForeign(String raw)throws Exception{
        Object h=retirement(raw);Method method=h.getClass().getDeclaredMethod("foreign",Set.class);method.setAccessible(true);
        try{return (String)method.invoke(h,Collections.<Integer>emptySet());}
        catch(InvocationTargetException wrapped){Throwable cause=wrapped.getCause();if(cause instanceof Exception)throw (Exception)cause;throw (Error)cause;}
    }
    private static void retirementSame(String raw)throws Exception{
        Object h=retirement(raw);Method method=h.getClass().getDeclaredMethod("requireSame",h.getClass(),Set.class,long.class);method.setAccessible(true);
        try{method.invoke(h,retirement(raw),Collections.<Integer>emptySet(),Long.valueOf(0));}
        catch(InvocationTargetException wrapped){Throwable cause=wrapped.getCause();if(cause instanceof Exception)throw (Exception)cause;throw (Error)cause;}
    }
    private static String productionCanonical(JSONObject value)throws Exception{
        Method method=PublicProfileRecentHistory.class.getDeclaredMethod("canonical",Object.class);
        method.setAccessible(true);
        return (String)method.invoke(null,value);
    }
    private static JSONObject projection(String raw)throws Exception{
        PublicOwnGroupPhysicalFence.RecentCensus c=PublicOwnGroupPhysicalFence.inspectRecents(raw);
        JSONObject out=new JSONObject();
        try{JSONObject h=new JSONObject(history(raw).evidence());
            out.put("history_normalized_sha256",h.getString("normalized_history_sha256"));
            out.put("history_evidence_canonical_sha256",ProfileIdentity.sha(productionCanonical(h)));
            out.put("history_record_count",h.getInt("history_record_count"));
            out.put("hidden_label_count",h.getInt("hidden_label_count"));
            out.put("raw_bytes",h.getInt("raw_bytes"));
        }catch(IllegalArgumentException expected){yes(expected.getMessage().startsWith("PUBLIC_HISTORY_"),"unexpected old history refusal");out.put("profile_absence_refusal",expected.getMessage());}
        try{JSONObject n=new JSONObject(notes(raw).evidence());
            out.put("notes_history_canonical_sha256",ProfileIdentity.sha(productionCanonical(n)));
        }catch(IllegalArgumentException expected){yes(expected.getMessage().startsWith("NOTES_HISTORY_"),"unexpected Notes absence refusal");out.put("notes_absence_refusal",expected.getMessage());}
        out.put("retirement_history_foreign_sha256",ProfileIdentity.sha(retirementForeign(raw)));
        out.put("raw_sha256",c.rawSha256);
        out.put("physical_projection_sha256",ProfileIdentity.sha(c.historyExcept(Collections.<Integer>emptySet())));

        List<String> identities=new ArrayList<String>();
        for(PublicOwnGroupPhysicalFence.RecentRecord r:c.records.values())identities.add(r.identity);
        out.put("record_identities",identities);
        out.put("all_ids",new ArrayList<Integer>(c.allIds));
        out.put("hidden_labels",new JSONObject(c.hiddenLabels));
        return out;
    }
    private static void accepted(String name,String raw,int expectedRows,int expectedController,int display)throws Exception{
        pass(name,()->{
            ProfileTaskPolicy.Recents low=ProfileTaskPolicy.Recents.parse(raw);
            PublicOwnGroupPhysicalFence.RecentCensus c=PublicOwnGroupPhysicalFence.inspectRecents(raw);
            yes(c.records.size()==expectedRows,"wrong record count");
            yes(c.records.keySet().equals(low.rows.keySet()),"independent low-level membership changed");
            Set<Integer> union=new LinkedHashSet<Integer>(c.records.keySet());union.addAll(c.hiddenLabels.keySet());
            yes(c.allIds.equals(union),"hidden/internal membership dropped");
            yes(c.hiddenLabels.size()==2,"hidden labels dropped");
            for(String label:c.hiddenLabels.values())
                yes(c.historyExcept(Collections.<Integer>emptySet()).contains(label),"hidden label absent from complete projection");
            yes(c.rawSha256.equals(ProfileIdentity.sha(raw.getBytes(StandardCharsets.UTF_8))),"raw bytes changed");
            PublicProfileRecentHistory.Snapshot snapshot=history(raw);
            JSONObject e=new JSONObject(snapshot.evidence());
            yes(e.getString("raw_text").equals(raw)&&e.getInt("raw_bytes")==raw.getBytes(StandardCharsets.UTF_8).length,"history changed raw");
            yes(e.getString("raw_sha256").equals(c.rawSha256),"raw SHA differs");
            yes(e.getInt("history_record_count")==expectedRows&&e.getInt("hidden_label_count")==2,"history membership loss");
            yes(!e.getBoolean("serialized_task_ids_grant_authority"),"history granted action authority");
            snapshot.requireSame(history(raw),0);
            PublicProfileRecentHistory.requireSameEvidence(e,new JSONObject(history(raw).evidence()),TARGET,0);
            PublicProfileRecentHistory.Baseline b=new PublicProfileRecentHistory.Baseline(snapshot,1000);
            yes(b.originalIds().equals(c.allIds),"baseline omitted observed internal/hidden task");
            PublicPersonalNotesHistory.Snapshot n=notes(raw);JSONObject ne=new JSONObject(n.evidence());
            yes(ne.getString("raw_text").equals(raw)&&ne.getString("raw_sha256").equals(c.rawSha256),"Notes history altered raw");
            yes(ne.getInt("history_record_count")==expectedRows&&ne.getInt("hidden_label_count")==2,"Notes history lost rows");
            yes(!ne.getBoolean("serialized_task_ids_grant_authority")&&!ne.getBoolean("whole_personal_profile_empty_claimed"),"Notes history claimed authority");
            n.requireSameForeign(notes(raw),0);
            PublicPersonalNotesHistory.requireSameEvidence(ne,new JSONObject(notes(raw).evidence()),NOTES,0);
            String retire=retirementForeign(raw);retirementSame(raw);
            for(String label:c.hiddenLabels.values())yes(retire.contains(label),"retirement lost hidden history");
            if(expectedController>0)yes(retire.contains(c.records.get(expectedController).label),"retirement erased controller");
            yes(new JSONObject(b.evidence()).getJSONArray("owned_task_ids").length()==0,"serialized controller became owned");
            if(expectedController>0){
                PublicOwnGroupPhysicalFence.RecentRecord r=c.records.get(expectedController);
                yes(r!=null&&r.user==0&&r.uid==10481&&r.root==expectedController&&r.display==display,"controller identity changed");
                yes(MAIN_FULL.equals(r.base)&&MAIN_FULL.equals(r.activity)&&"18800000".equals(r.flags),"controller fields changed");
                yes(b.originalIds().contains(expectedController),"controller erased from protection");
            }
        });
    }
    private static String refusal(Work body)throws Exception{
        try{body.run();}
        catch(IllegalArgumentException|IllegalStateException expected){
            String code=expected.getMessage();
            yes(code!=null&&(code.startsWith("PHYSICAL_")||code.startsWith("PUBLIC_HISTORY_")||code.startsWith("NOTES_HISTORY_")||code.startsWith("NOTES_RETIREMENT_")),"non-policy exception: "+code);
            return code;
        }
        throw new AssertionError("malformed/unsupported census was accepted");
    }
    private static void rejected(String name,String raw,String exact)throws Exception{
        String physical=refusal(()->PublicOwnGroupPhysicalFence.inspectRecents(raw));
        String rich=refusal(()->history(raw));
        String personal=refusal(()->notes(raw)),retired=refusal(()->retirement(raw));
        yes(physical.equals(rich)&&physical.equals(personal)&&physical.equals(retired),"a history consumer bypassed physical refusal");
        if(exact!=null)yes(exact.equals(physical),"wrong refusal: "+physical+" expected "+exact);
        REFUSALS.put(new JSONObject().put("case",name).put("physical",physical).put("history",rich).put("personal",personal).put("retirement",retired));
        CASES.put(name);
    }
    private static String read(JSONObject f)throws Exception{
        byte[] raw=Files.readAllBytes(Paths.get(f.getString("path")));
        yes(raw.length==f.getInt("bytes"),"private fixture bytes changed");
        yes(ProfileIdentity.sha(raw).equals(f.getString("sha256")),"private fixture SHA changed");
        return new String(raw,StandardCharsets.UTF_8);
    }
    public static void main(String[] args)throws Exception{
        if(args.length!=2)throw new IllegalArgumentException("mode and input spec required");
        boolean baseline="baseline".equals(args[0]);
        NOTES=new PersonalNotesAbsenceHostTest.Fixture().request();
        yes(baseline||"candidate".equals(args[0]),"mode");
        JSONObject spec=new JSONObject(new String(Files.readAllBytes(Paths.get(args[1])),StandardCharsets.UTF_8));
        Map<String,String> positives=new LinkedHashMap<String,String>();
        positives.put("synthetic_home",home());positives.put("synthetic_controller",controller());
        JSONArray actual=spec.getJSONArray("actual");
        for(int i=0;i<actual.length();i++){
            JSONObject f=actual.getJSONObject(i);
            positives.put(f.getString("name"),read(f));
        }
        JSONObject parity=new JSONObject();
        parity.put("synthetic_full_visible",projection(visible()));
        JSONArray legacy=spec.getJSONArray("legacy");
        for(int i=0;i<legacy.length();i++){
            JSONObject f=legacy.getJSONObject(i);parity.put(f.getString("name"),projection(read(f)));
        }
        JSONArray business=spec.getJSONArray("business");
        for(int i=0;i<business.length();i++){JSONObject f=business.getJSONObject(i);String raw=read(f);
            JSONObject view=projection(raw);parity.put(f.getString("name"),view);
            yes(raw.contains("  Visible recent tasks (most recent first):\n"),"business original lost actual visible header");
            yes("NOTES_HISTORY_TARGET_ALIAS_PRESENT".equals(view.optString("notes_absence_refusal")),"actual Notes task was called absent");
        }
        CASES.put("full_visible_projections_recorded");
        if(baseline){
            for(Map.Entry<String,String> item:positives.entrySet()){
                // This is the same positive API call the candidate must accept.
                ProfileTaskPolicy.Recents.parse(item.getValue());
                rejected("baseline_positive_rejected_"+item.getKey(),item.getValue(),"PHYSICAL_RECENTS_SECTIONS_INCOMPLETE");
            }
        }else{
            accepted("synthetic_home",home(),3,-1,-1);
            accepted("synthetic_controller",controller(),4,900,7);
            for(int i=0;i<actual.length();i++){
                JSONObject f=actual.getJSONObject(i);
                accepted(f.getString("name"),positives.get(f.getString("name")),f.getInt("rows"),f.getInt("controller"),f.getInt("display"));
            }
            final String raw=controller();
            rejected("controller_wrong_uid",raw.replace("u0a481","u0a482").replace("10481:org.trillionnium.hepta.local","10482:org.trillionnium.hepta.local"),"PHYSICAL_OMITTED_VISIBLE_NON_HOME");
            rejected("controller_wrong_user",raw.replace("userId=0 effectiveUid=u0a481","userId=10 effectiveUid=u10a481").replace("ActivityRecord{ca900 u0","ActivityRecord{ca900 u10"),"PHYSICAL_OMITTED_VISIBLE_NON_HOME");
            rejected("controller_on_main",replace(raw,"lastDisplayId=7","lastDisplayId=0"),"PHYSICAL_OMITTED_VISIBLE_NON_HOME");
            rejected("controller_on_cover",replace(raw,"lastDisplayId=7","lastDisplayId=1"),"PHYSICAL_OMITTED_VISIBLE_NON_HOME");
            rejected("controller_wrong_flags",replace(raw,"flg=0x18800000","flg=0x18000000"),"PHYSICAL_OMITTED_VISIBLE_NON_HOME");
            rejected("controller_wrong_root",replace(raw,"taskId=900 rootTaskId=900","taskId=900 rootTaskId=901"),"PHYSICAL_OMITTED_VISIBLE_NON_HOME");
            rejected("controller_empty_activity",replace(raw,"Activities=[ActivityRecord{ca900 u0 "+MAIN+" t900}]","Activities=[]"),"PHYSICAL_OMITTED_VISIBLE_CONTROLLER_ACTIVITY");
            rejected("controller_activity_task_mismatch",replace(raw," t900}]"," t901}]"),"PHYSICAL_OMITTED_VISIBLE_CONTROLLER_ACTIVITY");
            rejected("other_standard_app",raw.replace("org.trillionnium.hepta.local","com.example.other"),"PHYSICAL_OMITTED_VISIBLE_NON_HOME");
            rejected("multiple_controller_rows",header()+controllerRow(0,900,7)+controllerRow(1,901,8)+homeRow(2,101,0)+homeRow(3,102,1)+homeRow(4,103,0),"PHYSICAL_OMITTED_VISIBLE_MULTIPLE_CONTROLLERS");
            rejected("home_on_virtual_display",replace(home(),"    lastDisplayId=1","    lastDisplayId=7"),"PHYSICAL_OMITTED_VISIBLE_HOME");
            rejected("home_nonpersonal_user",home().replace("userId=0 effectiveUid=u0a100","userId=10 effectiveUid=u10a100"),"PHYSICAL_OMITTED_VISIBLE_HOME");
            rejected("home_null_component",home().replace("mActivityComponent=com.example.launcher/.Home","mActivityComponent=null"),"PHYSICAL_OMITTED_VISIBLE_HOME");
            rejected("missing_activity_type",replace(raw,"    autoRemoveRecents=true isPersistable=false activityType=1\n",""),"PHYSICAL_OMITTED_VISIBLE_TYPE");
            rejected("missing_final_newline",raw.substring(0,raw.length()-1),"PHYSICAL_OMITTED_VISIBLE_PARTIAL_SECTION");
            rejected("truncated_last_display",raw.substring(0,raw.lastIndexOf("    lastDisplayId=")),"PHYSICAL_RECENT_DISPLAY_MISSING");
            rejected("partial_visible_heading",raw+"  Visible recent tasks (most recent\n","PHYSICAL_OMITTED_VISIBLE_PARTIAL_SECTION");
            rejected("partial_visible_task_header",raw+"  * RecentTaskInfo #\n",null);
            rejected("unindented_partial_trailer",replace(raw,"    lastDisplayId=7","  BROKEN_SECTION\n    lastDisplayId=7"),"PHYSICAL_OMITTED_VISIBLE_PARTIAL_SECTION");
            rejected("explicit_empty_visible_heading",raw+"  Visible recent tasks (most recent first):\n","PHYSICAL_VISIBLE_RECENTS_MISSING");
            rejected("nonsequential_internal_index",replace(raw,"  * Recent #3:","  * Recent #9:"),null);
            rejected("incomplete_transport_marker",raw+"Output truncated\n","PHYSICAL_DUMP_INCOMPLETE");
            for(int i=0;i<business.length();i++){
                JSONObject f=business.getJSONObject(i);String original=read(f);
                int visibleAt=original.indexOf("  Visible recent tasks (most recent first):\n");
                yes(visibleAt>0&&visibleAt==original.lastIndexOf("  Visible recent tasks (most recent first):\n"),"actual business sections differ");
                String synthetic=original.substring(0,visibleAt);
                yes(ProfileTaskPolicy.Recents.parse(original).rows.keySet().equals(ProfileTaskPolicy.Recents.parse(synthetic).rows.keySet()),"synthetic presentation drop lost internal membership");
                rejected("synthetic_removed_visible_business_is_unsupported_"+f.getString("name"),synthetic,"PHYSICAL_OMITTED_VISIBLE_NON_HOME");
            }
            pass("hidden_unknown_profile_stays_unresolved",()->{
                String hidden=replace(home(),"A=10101:com.example.hidden","A=1010101:com.example.hidden");
                PublicOwnGroupPhysicalFence.RecentCensus c=PublicOwnGroupPhysicalFence.inspectRecents(hidden);
                yes(c.hiddenLabels.containsKey(778)&&c.allIds.contains(778),"unknown hidden label dropped");
                String code=refusal(()->history(hidden));
                yes("PUBLIC_HISTORY_DETACHED_PROFILE_HIDDEN_UNKNOWN".equals(code),"unknown profile label became absent");
            });
            pass("omitted_visible_does_not_erase_controller_or_hidden_history",()->{
                String code=refusal(()->history(raw).requireSame(history(home()),0));
                yes("PUBLIC_HISTORY_CHANGED".equals(code),"controller disappeared from protected history");
                String changed=replace(home(),"Task{aaa77 #777","Task{aaa79 #777");
                code=refusal(()->history(home()).requireSame(history(changed),0));
                yes("PUBLIC_HISTORY_CHANGED".equals(code),"hidden identity disappeared from protected history");
            });
        }
        JSONObject result=new JSONObject();
        result.put("schema","hepta.empty-visible-recents-focused.v1");
        result.put("mode",args[0]);result.put("all_pass",!baseline);result.put("expected_baseline_red",baseline);
        result.put("cases",CASES);result.put("case_count",CASES.length());result.put("assertions",assertions);
        result.put("refusals",REFUSALS);result.put("projection_fixtures",parity);
        result.put("actual_fixture_count",actual.length());result.put("legacy_fixture_count",legacy.length());
        result.put("portable_rows_are_synthetic",true);result.put("phone_operations",0);
        result.put("notes_request_fixture_synthetic",true);result.put("retirement_history_compiled_as_exact_body_extraction",true);
        result.put("retirement_coordinator_and_android_not_exercised",true);
        result.put("removed_visible_business_fixture_is_synthetic_not_observed_phone_shape",true);
        result.put("android_runtime",false);result.put("business_or_cleanup_proven",false);
        result.put("complete_transport_is_external_prerequisite",true);
        System.out.println(result.toString());
        if(baseline)System.exit(3);
    }
}
