package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;

/** Two separate retained phone pairs. Pure comparison only; no new phone read,
 * Session, model run, Android NodeRef, effect, or business result is fabricated. */
public final class NativeSearchRoleOriginalsHostTest {
    static int assertions;
    static final List<String> cases=new ArrayList<String>();
    static final String ACTION_SHA="dc3d3b1b81818f4a9e491828ba3a8a66efe76343521a5cc192c270d798ffe53e";
    static final String DIAGNOSTIC_SHA="599bf6fe9c470d770cd7a6ef2126763edb17c851103a7dad27731a39b7e382e1";
    interface Check {void run()throws Exception;}
    static void yes(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
    static void test(String name,Check body)throws Exception{body.run();cases.add(name);}
    static void rejects(Check body,String fragment)throws Exception{
        boolean rejected=false;try{body.run();}catch(IllegalArgumentException expected){rejected=true;
            if(fragment!=null)yes(expected.getMessage().contains(fragment),"wrong refusal: "+expected.getMessage());}
        yes(rejected,"expected rejection");
    }
    static JSONObject read(Path p,String expected)throws Exception{
        byte[] raw=Files.readAllBytes(p);yes(QualificationScope.hash(raw).equals(expected),"unchanged raw original: "+p.getFileName());
        return new JSONObject(new String(raw,StandardCharsets.UTF_8));
    }
    static NativeActionSnapshotCheck.Snapshot snapshot(JSONObject value)throws Exception{
        JSONObject copy=new JSONObject(value.toString());copy.remove("snapshot_sha256");
        return NativeSearchPlanning.readSnapshot(NativeSearchPlanning.map(copy));
    }
    static JSONObject serial(NativeActionSnapshotCheck.Snapshot value)throws Exception{
        return NativeSearchPlanning.json(NativeSearchPlanning.snapshot(value));
    }
    static JSONObject row(JSONObject snap,String path)throws Exception{
        JSONArray rows=snap.getJSONArray("nodes");for(int i=0;i<rows.length();i++){
            JSONObject n=rows.getJSONObject(i);if(path.equals(n.getString("path")))return n;
        }throw new AssertionError("missing test node "+path);
    }
    static NativeActionSnapshotCheck.Snapshot diagnostic(JSONObject value,Map<String,Object> adapter)throws Exception{
        // These two keys are absent from the old diagnostic and intentionally
        // synthetic. They are never borrowed from the earlier action pair.
        Map<String,Object> env=new TreeMap<String,Object>(NativeSearchPlanning.map(value.getJSONObject("identity")));
        JSONObject read=value.getJSONObject("read");
        env.put("origin_observation_id","eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
        env.put("installed_set_sha256",NativeActionSnapshotCheck.hash("host-only missing installed binding; not phone authority"));
        env.put("window_metadata_sha256",value.getString("window_metadata_sha256"));
        env.put("reported_windows_sha256",NativeAppEvidence.fingerprint(NativeSearchPlanning.map(read.getJSONObject("reported_windows"))));
        env.put("reported_windows_complete",read.getBoolean("reported_windows_complete"));
        env.put("ime_visibility",read.getString("ime_visibility"));
        // The old diagnostic did not persist the nativeActionCapturedAt field.
        // End time is a declared host adapter value, not a device census clock.
        env.put("captured_elapsed_ms",read.getLong("read_completed_elapsed_ms"));
        env.put("full_native_complete",read.getBoolean("native_observation_complete")&&!read.getBoolean("truncated")&&value.getBoolean("native_nodes_complete"));
        env.put("visited",read.getInt("visited_nodes"));env.put("pending",read.getInt("pending_nodes_at_stop"));
        env.put("node_omissions",read.getInt("nodes_omitted_by_node_limit"));
        env.put("text_omissions",read.getInt("nodes_omitted_by_text_limit"));
        env.put("child_omissions",read.getInt("child_slots_omitted_by_traversal_limit"));
        JSONObject encoded=new JSONObject();encoded.put("envelope",NativeSearchPlanning.json(env));encoded.put("nodes",value.getJSONArray("native_nodes"));
        NativeActionSnapshotCheck.Snapshot result=snapshot(encoded);
        yes(NativeSearchPlanning.equal(NativeSearchPlanning.snapshot(result).get("nodes"),NativeSearchPlanning.map(encoded).get("nodes")),"diagnostic native rows preserved exactly as values");
        Map<String,Object> source=new LinkedHashMap<String,Object>();
        source.put("identity",NativeSearchPlanning.map(value.getJSONObject("identity")));
        source.put("read_interval",Arrays.asList(read.getLong("read_started_elapsed_ms"),read.getLong("read_completed_elapsed_ms")));
        source.put("raw_nodes_sha256",NativeAppEvidence.fingerprint(NativeSearchPlanning.snapshot(result).get("nodes")));
        source.put("reported_windows",NativeSearchPlanning.map(read.getJSONObject("reported_windows")));
        source.put("window_metadata_sha256",value.getString("window_metadata_sha256"));
        source.put("synthetic_missing_keys",Arrays.asList("origin_observation_id","installed_set_sha256"));
        source.put("captured_elapsed_ms_source","HOST ADAPTER ONLY: original read_completed_elapsed_ms; no actual native census clock was present");
        source.put("new_phone_census_claimed",false);source.put("new_action_authority_claimed",false);
        adapter.put(adapter.isEmpty()?"before":"after",source);return result;
    }
    static void antichain(NativeSearchRole role){
        for(String a:role.enclosures)for(String b:role.enclosures)if(!a.equals(b))yes(!a.startsWith(b+"/"),"nonoverlapping enclosure antichain");
        Object raw=role.evidence().get("changed_path_classification");yes(raw instanceof Map,"complete classification");
        yes(((Map<?,?>)raw).size()==role.changedPaths.size(),"exactly one classification per actual changed path");
        yes(Boolean.FALSE.equals(role.evidence().get("grants_dispatch")),"pure proof grants no dispatch");
        yes(Boolean.FALSE.equals(role.evidence().get("query_or_price_verified")),"pure proof grants no price completion");
    }
    static void galleryGeometricCause(NativeActionSnapshotCheck.Snapshot a,NativeActionSnapshotCheck.Snapshot b){
        yes(NativeActionSnapshotCheck.searchPlanningRoleFacts(a).equals(NativeActionSnapshotCheck.searchPlanningRoleFacts(b)),"actual search and all navigation semantic facts remain equal");
        for(String p:Arrays.asList("0/0/1/5","0/0/1","0/0","0"))yes(a.node(p).v.equals(b.node(p).v),"gallery root and real ancestor fixed: "+p);
        for(NativeActionSnapshotCheck.Snapshot snap:Arrays.asList(a,b)){
            List<Integer> enclosure=snap.node("0/0/1/5").bounds,nav=snap.node("0/5").bounds;
            yes(Math.max(enclosure.get(0),nav.get(0))<Math.min(enclosure.get(2),nav.get(2))
                &&Math.max(enclosure.get(1),nav.get(1))<Math.min(enclosure.get(3),nav.get(3)),"actual gallery rectangle intersects selected-home navigation");
            for(NativeActionSnapshotCheck.Node n:snap.nodes.values())if(n.path.equals("0/0/1/5")||n.path.startsWith("0/0/1/5/")){
                List<Integer> r=n.bounds;boolean positive=r.get(0)<r.get(2)&&r.get(1)<r.get(3);
                if(Boolean.TRUE.equals(n.v.get("visible")))yes(positive,"actual gallery visible node has positive rectangle");
                if(positive)yes(r.get(0)>=enclosure.get(0)&&r.get(1)>=enclosure.get(1)&&r.get(2)<=enclosure.get(2)&&r.get(3)<=enclosure.get(3),"actual gallery footprint already within its fixed enclosure");
                else for(NativeActionSnapshotCheck.Node child:snap.nodes.values())if(child.path.startsWith(n.path+"/"))
                    yes(!Boolean.TRUE.equals(child.v.get("visible")),"actual nonpositive hidden subtree has no visible descendant");
            }
        }
        yes(!a.node("0/0/1/5/0").v.equals(b.node("0/0/1/5/0").v),"inner pager is itself changed, not a fixed alternative enclosure");
    }
    public static void main(String[] args)throws Exception{
        Path originals=Paths.get(args[0]),output=Paths.get(args[1]);
        JSONObject action=read(originals.resolve("step-01-action.json"),ACTION_SHA);
        JSONObject execution=action.getJSONObject("action_execution");
        JSONObject rawAction=execution.getJSONObject("native_action_rejection_census");
        final NativeActionSnapshotCheck.Snapshot a=snapshot(rawAction.getJSONObject("before")),b=snapshot(rawAction.getJSONObject("fresh"));
        test("real_83_84_original_snapshots_are_exact",()->{
            yes(a.nodes.size()==83&&b.nodes.size()==84,"separate real action pair counts");
            yes(a.sha.equals(rawAction.getJSONObject("before").getString("snapshot_sha256")),"original A canonical SHA unchanged");
            yes(b.sha.equals(rawAction.getJSONObject("fresh").getString("snapshot_sha256")),"original B canonical SHA unchanged");
            yes(!action.getBoolean("accepted")&&!action.getBoolean("dispatched")&&action.getBoolean("stale"),"original refusal remains original fact");
            yes(!execution.getBoolean("effect_entered")&&!execution.getBoolean("effect_returned"),"no original phone effect");
        });
        test("real_83_84_old_click_still_rejected_same_protected_path",()->{
            Map<String,Object> identity=new TreeMap<String,Object>();for(String key:NativeActionSnapshotCheck.PROFILE_AUTHORITY)identity.put(key,a.env.get(key));
            NativeActionSnapshotCheck.Node target=a.node(rawAction.getString("target_path"));
            NativeActionSnapshotCheck.Intent old=new NativeActionSnapshotCheck.Intent(rawAction.getString("purpose"),NativeActionSnapshotCheck.XIAOMI,
                target.path,target.label,(String)target.v.get("ref_signature_sha256"),rawAction.getString("model_run_id"),rawAction.getString("original_node_id"),
                rawAction.getString("original_action_sha256"),null,identity,execution.getLong("queued_elapsed_ms"),execution.getLong("deadline_elapsed_ms"));
            rejects(()->NativeActionSnapshotCheck.compare(old,a,b,rawAction.getLong("compared_elapsed_ms")),rawAction.getString("comparison_refusal"));
        });
        test("real_83_84_new_role_also_rejects_gallery_overlapping_navigation",()->{
            galleryGeometricCause(a,b);
            rejects(()->NativeSearchRole.compare(a,b),"changed node has no fixed complete disjoint enclosure: 0/0/1/5/0");
        });
        JSONObject rawDiagnostic=read(originals.resolve("failed-native-census.json"),DIAGNOSTIC_SHA);
        Map<String,Object> adapter=new LinkedHashMap<String,Object>();
        final NativeActionSnapshotCheck.Snapshot c=diagnostic(rawDiagnostic.getJSONObject("before"),adapter),d=diagnostic(rawDiagnostic.getJSONObject("after"),adapter);
        final NativeSearchRole[] observationRole=new NativeSearchRole[1];
        test("separate_real_84_84_diagnostic_eleven_differences",()->{
            yes(c.nodes.size()==84&&d.nodes.size()==84,"later pair is independent, not the action pair");
            NativeSearchRole role=NativeSearchRole.compare(c,d);observationRole[0]=role;
            yes(!role.fullTreeEqual&&role.changedPaths.size()==11,"all eleven later differences retained");
            yes(role.enclosures.equals(Collections.singletonList("0/0/1/1/0")),"fixed complete carousel RecyclerView enclosure; unchanged gallery is not invented");
            antichain(role);yes("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".equals(role.authority.get("origin_observation_id")),"synthetic adapter origin is explicit, never earlier action authority");
        });
        test("identical_complete_tree_claim_is_true_only_when_equal",()->{NativeSearchRole role=NativeSearchRole.compare(c,c);yes(role.fullTreeEqual&&role.changedPaths.isEmpty(),"actual equal pure pair");antichain(role);});
        test("raw_visible_zero_area_rejected_even_when_Node_visible_false",()->{
            JSONObject changed=serial(d);row(changed,"0/0/1/1/0/0").put("bounds",new JSONArray(Arrays.asList(10,1033,10,1368))).put("visible",true);
            NativeActionSnapshotCheck.Snapshot candidate=snapshot(changed);yes(!candidate.node("0/0/1/1/0/0").visible(),"old visibility predicate folds area");
            rejects(()->NativeSearchRole.compare(c,candidate),"no fixed complete disjoint enclosure");
        });
        test("raw_visible_inverted_area_rejected",()->{
            JSONObject changed=serial(d);row(changed,"0/0/1/1/0/0").put("bounds",new JSONArray(Arrays.asList(100,1033,10,1368))).put("visible",true);
            rejects(()->NativeSearchRole.compare(c,snapshot(changed)),"no fixed complete disjoint enclosure");
        });
        test("hidden_nonpositive_parent_with_visible_descendant_rejected",()->{
            JSONObject changed=serial(d);row(changed,"0/0/1/1/0/0").put("bounds",new JSONArray(Arrays.asList(10,1033,10,1368))).put("visible",false);
            yes(row(changed,"0/0/1/1/0/0/0").getBoolean("visible"),"visible descendant retained");
            rejects(()->NativeSearchRole.compare(c,snapshot(changed)),"no fixed complete disjoint enclosure");
        });
        test("visible_overflow_outside_fixed_enclosure_rejected",()->{
            JSONObject changed=serial(d);row(changed,"0/0/1/1/0/1/0").put("bounds",new JSONArray(Arrays.asList(-1,1033,200,1368)));
            rejects(()->NativeSearchRole.compare(c,snapshot(changed)),"no fixed complete disjoint enclosure");
        });
        test("actual_parent_overflow_inside_fixed_enclosure_is_not_repaired",()->{
            NativeActionSnapshotCheck.Node parent=d.node("0/0/1/1/0/3"),child=d.node("0/0/1/1/0/3/0");
            yes(child.bounds.get(0)<parent.bounds.get(0),"actual child extends left of immediate parent");
            yes(child.bounds.get(0)>=d.node("0/0/1/1").bounds.get(0),"actual child remains in fixed complete enclosure");
            NativeSearchRole.compare(c,d);yes(d.node(child.path).bounds.equals(child.bounds),"original geometry unchanged");
        });
        test("changed_fixed_enclosure_ancestor_rejected",()->{
            JSONObject changed=serial(d);row(changed,"0/0/1").put("selected",true);
            rejects(()->NativeSearchRole.compare(c,snapshot(changed)),"no fixed complete disjoint enclosure");
        });
        test("changed_shared_actual_search_ancestor_rejected",()->{
            JSONObject changed=serial(d);row(changed,"0/0").put("selected",true);
            rejects(()->NativeSearchRole.compare(c,snapshot(changed)),"actual role ancestor changed");
        });
        test("hint_literal_without_recomputed_reference_rejected",()->{
            JSONObject changed=serial(d);row(changed,"0/0/3/0/0").put("text","HOST MUTATION unrelated to observed hint reference");
            rejects(()->NativeSearchRole.compare(c,snapshot(changed)),null);
        });
        test("search_target_fixed_bounds_change_rejected",()->{
            JSONObject changed=serial(d);row(changed,"0/0/3").put("bounds",new JSONArray(Arrays.asList(155,287,1000,375)));
            rejects(()->NativeSearchRole.compare(c,snapshot(changed)),null);
        });
        test("search_icon_change_rejected",()->{
            JSONObject changed=serial(d);row(changed,observationRole[0].iconPath).put("selected",true);
            rejects(()->NativeSearchRole.compare(c,snapshot(changed)),null);
        });
        test("new_editable_role_in_variable_region_rejected",()->{
            JSONObject changed=serial(d);row(changed,"0/0/1/1/0/1/0").put("editable",true);
            rejects(()->NativeSearchRole.compare(c,snapshot(changed)),null);
        });
        test("missing_complete_child_slot_rejected",()->{
            JSONObject changed=serial(d);JSONArray rows=changed.getJSONArray("nodes");
            for(int i=0;i<rows.length();i++)if(rows.getJSONObject(i).getString("path").equals("0/0/1/1/0/1/0")){rows.remove(i);break;}
            changed.getJSONObject("envelope").put("visited",rows.length());rejects(()->snapshot(changed),"missing child slot");
        });
        test("foreign_node_window_rejected",()->{JSONObject changed=serial(d);row(changed,"0/0/1/1/0/1/0").put("window_id",0);rejects(()->snapshot(changed),"foreign node/window");});
        test("foreign_node_package_rejected",()->{JSONObject changed=serial(d);row(changed,"0/0/1/1/0/1/0").put("package","host.foreign");rejects(()->snapshot(changed),"foreign node/window");});
        test("unknown_ime_is_never_filled_hidden",()->{JSONObject changed=serial(d);changed.getJSONObject("envelope").put("ime_visibility","unknown");rejects(()->snapshot(changed),"known hidden IME");});
        test("owner_change_rejected",()->{JSONObject changed=serial(d);changed.getJSONObject("envelope").put("owner_sha256",NativeActionSnapshotCheck.hash("host other owner"));rejects(()->NativeSearchRole.compare(c,snapshot(changed)),"ownership changed");});
        test("profile_full_uid_change_rejected",()->{JSONObject changed=serial(d);changed.getJSONObject("envelope").put("profile_full_uid",1010486);rejects(()->NativeSearchRole.compare(c,snapshot(changed)),"ownership changed");});
        test("pure_snapshot_and_proof_are_deep_immutable",()->{
            JSONObject changed=serial(d);NativeActionSnapshotCheck.Snapshot immutable=snapshot(changed);String hash=immutable.sha;
            row(changed,"0/0/3").put("selected",true);yes(hash.equals(immutable.sha)&&!Boolean.TRUE.equals(immutable.node("0/0/3").v.get("selected")),"input mutation cannot change pure snapshot");
            boolean refused=false;try{immutable.node("0/0/3").v.put("selected",true);}catch(UnsupportedOperationException expected){refused=true;}yes(refused,"node values immutable");
        });
        Map<String,Object> report=new LinkedHashMap<String,Object>();report.put("schema","hepta.native-search-original-pairs-host-gate.v1");
        report.put("all_pass",true);report.put("cases",cases.size());report.put("assertions",assertions);report.put("case_names",cases);
        report.put("action_original_sha256",ACTION_SHA);report.put("diagnostic_original_sha256",DIAGNOSTIC_SHA);
        report.put("action_pair_new_role_accepted",false);report.put("action_pair_new_role_refusal","changed node has no fixed complete disjoint enclosure; actual gallery/navigation geometric overlap retained");
        report.put("separate_diagnostic_pair_role",observationRole[0].evidence());
        report.put("diagnostic_adapter_provenance",adapter);report.put("phone_actions",0);report.put("new_android_census_claimed",false);
        report.put("new_model_or_dispatch_claimed",false);report.put("business_verified",false);
        Files.write(output,(NativeSearchPlanning.json(report).toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        System.out.println("PASS original pairs cases="+cases.size()+" assertions="+assertions);
    }
}
