package org.trillionnium.hepta.local;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.TreeSet;
import java.util.zip.GZIPInputStream;
import org.json.JSONArray;
import org.json.JSONObject;

/** Unchanged R6 observation bytes, replayed only into detached parser facts.
 * Authority/completion bindings below are explicitly host synthetic. Reading
 * this historical evidence neither reproduces a phone click nor verifies the
 * installed App, an Android node, model action, or product-price completion. */
final class NativeXiaomiEntryObservationHostTest {
    private static final String OWNER="在小米商城查一下小米AX3000T的售价";
    private static final NativeAppGoal GOAL=NativeAppGoal.parse(OWNER,NativeAppGoal.XIAOMI_PACKAGE);
    private static final String[] NAMES={"loading","home","login"};
    private static final String[] HASHES={"178b6c9f3f08bc958fca44c6f5f517481b73048a386df930de27c33e8a927690",
            "0f7758a5af8d2ff79da2ebb8f973980ce3d73e50f6b2ec5db38df3c5a4d5bc9c",
            "85eec05bd99fdd7dcbc65b8fc2cdcb4234c1907051860d08afb9936d4d5a165e"};
    private NativeXiaomiEntryObservationHostTest(){}
    private static String hash(String value){return NativeAppEvidence.hash(value);}
    private static byte[] unpack(Path path)throws Exception{
        ByteArrayOutputStream out=new ByteArrayOutputStream();
        try(GZIPInputStream in=new GZIPInputStream(new ByteArrayInputStream(Files.readAllBytes(path)))){
            byte[] buffer=new byte[4096];int count;
            while((count=in.read(buffer))!=-1){out.write(buffer,0,count);if(out.size()>200000)throw new IllegalArgumentException("fixture size");}
        }return out.toByteArray();
    }
    private static NativeAppEvidence.Frame frame(JSONObject raw,String recordHash){
        List<NativeAppEvidence.Node> nodes=new ArrayList<NativeAppEvidence.Node>();JSONArray all=raw.getJSONArray("nodes");
        for(int i=0;i<all.length();i++){
            JSONObject n=all.getJSONObject(i),position=n.getJSONObject("native_tree_position"),selection=n.getJSONObject("native_selection_state");
            JSONArray b=n.getJSONArray("bounds"),directions=n.getJSONArray("scroll_directions");TreeSet<String> scroll=new TreeSet<String>();
            for(int d=0;d<directions.length();d++)scroll.add(directions.getString(d));
            String text=n.optString("text",""),description=n.optString("description","");
            String label=ObservedTargetLabels.project(!text.isEmpty()?text:!description.isEmpty()?description:n.optString("child_text",""));
            boolean observed=selection.getBoolean("observed");
            nodes.add(new NativeAppEvidence.Node(n.getString("id"),n.getString("package"),n.getString("class_name"),n.optString("view_id",""),
                    text,description,position.getString("path"),position.getString("parent_class"),n.getString("node_app_tree_sha256"),label,
                    b.getInt(0),b.getInt(1),b.getInt(2),b.getInt(3),n.optBoolean("enabled",true),n.optBoolean("password",false),
                    n.optBoolean("clickable",false),n.optBoolean("editable",false),n.optBoolean("scrollable",false),
                    observed?Boolean.valueOf(selection.getBoolean("selected")):null,observed?Boolean.valueOf(selection.getBoolean("checkable")):null,
                    observed?Boolean.valueOf(selection.getBoolean("checked")):null,scroll));
        }
        JSONObject window=raw.getJSONObject("window"),background=raw.getJSONObject("background_session"),c=raw.getJSONObject("collection");
        JSONArray b=window.getJSONArray("bounds");
        boolean complete=c.getInt("retained_nodes")==nodes.size()&&c.getInt("pending_nodes_at_stop")==0
                &&c.getInt("child_slots_omitted_by_traversal_limit")==0&&c.getInt("nodes_omitted_by_node_limit")==0
                &&c.getInt("nodes_omitted_by_text_limit")==0;
        return new NativeAppEvidence.Frame("11111111111111111111111111111111",GOAL.ownerSha256,hash("HOST_ONLY_TARGET"),hash("HOST_ONLY_AUTH"),
                hash("HOST_ONLY_SELECTION"),raw.getString("observation_id"),raw.getString("package"),background.getString("generation"),
                raw.getString("app_tree_sha256"),raw.getString("observation_state_sha256"),raw.getString("screen_sha256"),recordHash,
                hash("HOST_ONLY_COMPLETION_NOT_VERIFIED"),background.getInt("display_id"),raw.getInt("window_id"),raw.getInt("rotation"),
                raw.getInt("screen_width"),raw.getInt("screen_height"),b.getInt(0),b.getInt(1),b.getInt(2),b.getInt(3),raw.getLong("captured_elapsed_ms"),
                raw.getBoolean("nodes_truncated"),complete,nodes,window.getInt("type"),"observed".equals(window.getString("metadata_status")));
    }
    private static JSONObject copy(JSONObject value){return new JSONObject(value.toString());}
    private static JSONObject node(JSONObject value,String id){JSONArray a=value.getJSONArray("nodes");
        for(int i=0;i<a.length();i++)if(id.equals(a.getJSONObject(i).getString("id")))return a.getJSONObject(i);
        throw new AssertionError("recorded node missing");}
    static void run(Path source)throws Exception{
        final Path fixtures=source.resolve("tests/native-xiaomi-search-entry/fixtures");final JSONObject[] raw=new JSONObject[3];
        IntegrationChecks.one("r6_entry_replay_original_bytes_and_explicit_provenance",()->{
            JSONObject provenance=new JSONObject(new String(Files.readAllBytes(fixtures.resolve("PROVENANCE.json")),StandardCharsets.UTF_8));
            IntegrationChecks.yes(provenance.getBoolean("host_replay_authority_binding_synthetic")&&!provenance.getBoolean("installed_identity_verified_by_replay"),"no installed identity or authority from replay");
            for(int i=0;i<NAMES.length;i++){
                byte[] bytes=unpack(fixtures.resolve(NAMES[i]+".json.gz"));String text=new String(bytes,StandardCharsets.UTF_8);
                IntegrationChecks.yes(HASHES[i].equals(hash(text)),"complete original observation byte hash: "+NAMES[i]);raw[i]=new JSONObject(text);
            }
        });
        IntegrationChecks.one("original_manual_result_identifies_switcher_not_adjacent_icon",()->{
            String text=new String(Files.readAllBytes(fixtures.resolve("manual-search-entry-RESULT.json")),StandardCharsets.UTF_8);
            IntegrationChecks.yes("275dd04b104cd0a784807658b46ea76038783104a933e50c997cb95852174acf".equals(hash(text)),"original RESULT bytes unchanged");
            JSONObject result=new JSONObject(text),target=result.getJSONObject("actual_target");
            IntegrationChecks.yes("com.xiaomi.shop.plugin.homepage:id/switcher".equals(target.getString("resource-id"))
                    &&"android.widget.ViewSwitcher".equals(target.getString("class"))&&"[156,287][1000,375]".equals(target.getString("bounds")),"recorded actual manual target");
            String xml=new String(Files.readAllBytes(source.resolve("tests/native-xiaomi-product/fixtures/search-entry.xml")),StandardCharsets.UTF_8);
            IntegrationChecks.yes(result.getJSONObject("after_tree").getString("sha256").equals(hash(xml)),"original after tree binds existing search-entry fixture");
            IntegrationChecks.yes(!result.getBoolean("model_executed")&&!result.getBoolean("business_verified"),"manual receipt not promoted to model success");
        });
        IntegrationChecks.one("r6_recorded_home_offers_only_actual_query_entry",()->{
            NativeAppEvidence.Frame f=frame(raw[1],HASHES[1]);NativeXiaomiProductPage.Page p=NativeXiaomiProductPage.inspect(GOAL,f);
            IntegrationChecks.yes(f.nodes.size()==59&&f.collectionComplete&&!f.nodesTruncated,"all retained original nodes and original counters");
            IntegrationChecks.yes("home_search".equals(p.phase)&&p.clickIds.equals(Collections.singleton("n16"))&&"open_search".equals(p.purposes.get("n16")),"current switcher is only offered entry");
            IntegrationChecks.yes("搜索小米电视 · 小米电视".equals(f.byId.get("n16").label)&&"0/0/3".equals(f.byId.get("n16").path),"actual label and path preserved");
            IntegrationChecks.yes(!p.clickIds.contains("n17")&&!p.clickIds.contains("n19")&&"搜索".equals(f.byId.get("n17").description)
                    &&"立即登录".equals(f.byId.get("n19").text),"neighbor and login remain distinct original facts");
            IntegrationChecks.yes(p.editValues.isEmpty()&&p.quote==null&&!Boolean.TRUE.equals(p.evidence().get("query_dispatched")),"entry does not submit a query or prove a price");
        });
        IntegrationChecks.one("r6_recorded_loading_has_no_search_click",()->{
            NativeXiaomiProductPage.Page p=NativeXiaomiProductPage.inspect(GOAL,frame(raw[0],HASHES[0]));
            IntegrationChecks.yes(NativeXiaomiProductPage.HOME_LOADING.equals(p.phase)&&p.clickIds.isEmpty()&&p.editValues.isEmpty(),"navigation-only loading remains wait-only");
        });
        IntegrationChecks.one("r6_recorded_login_offers_only_current_return",()->{
            NativeXiaomiProductPage.Page p=NativeXiaomiProductPage.inspect(GOAL,frame(raw[2],HASHES[2]));
            IntegrationChecks.yes(NativeXiaomiProductPage.LOGIN.equals(p.phase)&&p.clickIds.equals(Collections.singleton("n0"))
                    &&NativeXiaomiProductPage.LOGIN_EXIT.equals(p.purposes.get("n0"))&&p.editValues.isEmpty()&&p.quote==null,"no search, account, consent or price from login frame");
        });
        IntegrationChecks.one("r6_entry_replay_rejects_similar_wrong_control_class",()->{
            JSONObject changed=copy(raw[1]);node(changed,"n16").put("class_name","android.widget.ImageView");
            IntegrationChecks.yes(NativeXiaomiProductPage.inspect(GOAL,frame(changed,hash(changed.toString()))).clickIds.isEmpty(),"same resource or label cannot replace actual control class");
        });
        IntegrationChecks.one("r6_entry_replay_rejects_unrelated_rotating_hint",()->{
            JSONObject changed=copy(raw[1]);node(changed,"n27").put("description","立即登录");
            IntegrationChecks.yes(NativeXiaomiProductPage.inspect(GOAL,frame(changed,hash(changed.toString()))).clickIds.isEmpty(),"entry cannot be inferred from unrelated descendant");
        });
        IntegrationChecks.one("r6_entry_replay_rejects_foreign_target_package",()->{
            JSONObject changed=copy(raw[1]);node(changed,"n16").put("package","com.example.other");
            IntegrationChecks.yes(NativeXiaomiProductPage.inspect(GOAL,frame(changed,hash(changed.toString()))).clickIds.isEmpty(),"foreign target cannot inherit Xiaomi entry role");
        });
    }
}
