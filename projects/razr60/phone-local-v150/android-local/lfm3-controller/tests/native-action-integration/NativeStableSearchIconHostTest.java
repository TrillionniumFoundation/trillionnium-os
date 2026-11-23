package org.trillionnium.hepta.local;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

/** New default icon policy with exact existing XML values and explicit host
 * identity/Android doubles. No device navigation or business qualification. */
final class NativeStableSearchIconHostTest {
    private static final String OWNER="在小米商城查一下小米AX3000T的售价";
    private static final NativeAppGoal GOAL=NativeAppGoal.parse(OWNER,NativeAppGoal.XIAOMI_PACKAGE);
    private static int serial;
    private NativeStableSearchIconHostTest(){}
    interface Mutation {void apply(Map<String,Object> env,Map<String,Map<String,Object>> rows);}
    private static String hash(String s){return NativeAppEvidence.hash(s);}
    private static void yes(boolean v,String m){IntegrationChecks.yes(v,m);}
    private static void one(String n,IntegrationChecks.Work w)throws Exception{IntegrationChecks.one("stable_icon_"+n,w);}
    private static NativeAppEvidence.Frame frame(List<NativeAppEvidence.Node> nodes){
        String id=String.format(java.util.Locale.ROOT,"%032x",++serial);
        return new NativeAppEvidence.Frame("11111111111111111111111111111111",GOAL.ownerSha256,hash("HOST_TARGET"),hash("HOST_AUTH"),
                hash("HOST_SELECTION"),id,GOAL.packageName,"12345678-1234-4234-8234-123456789abc",hash("HOST_TREE"+id),hash("HOST_STATE"+id),
                hash("HOST_SCREEN_NOT_OBSERVED"+id),hash("HOST_RECORD"+id),hash("HOST_COMPLETION"),31,7,0,1224,2992,0,0,1224,2992,
                1000+serial,false,true,nodes,1,true);
    }
    private static NativeAppEvidence.Frame xml(Path source,String name)throws Exception{
        return frame(NativeXmlFixture.read(source.resolve("tests/native-xiaomi-product/fixtures/"+name+".xml")).nodes);
    }
    private static NativeAppEvidence.Node icon(NativeAppEvidence.Frame f){
        NativeAppEvidence.Node found=null;for(NativeAppEvidence.Node n:f.nodes)if(n.viewId.endsWith(":id/searchIcon")){
            if(found!=null)throw new AssertionError("duplicate fixture icon");found=n;
        }if(found==null)throw new AssertionError("missing fixture icon");return found;
    }
    private static NativeAppEvidence.Node alter(NativeAppEvidence.Node n,String key,Object value){
        int[] b="bounds".equals(key)?(int[])value:new int[]{n.left,n.top,n.right,n.bottom};
        return new NativeAppEvidence.Node("id".equals(key)?(String)value:n.id,"package".equals(key)?(String)value:n.packageName,
                "class".equals(key)?(String)value:n.className,"view".equals(key)?(String)value:n.viewId,
                "text".equals(key)?(String)value:n.text,"description".equals(key)?(String)value:n.description,
                "path".equals(key)?(String)value:n.path,"parent".equals(key)?(String)value:n.parentClass,hash("HOST_MUTATION"+key+value),
                "label".equals(key)?(String)value:n.label,b[0],b[1],b[2],b[3],
                "enabled".equals(key)?(Boolean)value:n.enabled,"password".equals(key)?(Boolean)value:n.password,
                "clickable".equals(key)?(Boolean)value:n.clickable,"editable".equals(key)?(Boolean)value:n.editable,
                "scrollable".equals(key)?(Boolean)value:n.scrollable,"selected".equals(key)?(Boolean)value:n.selected,
                "checkable".equals(key)?(Boolean)value:n.checkable,"checked".equals(key)?(Boolean)value:n.checked,n.scrollDirections);
    }
    private static void providerNegative(Path source,String name,String key,Object value)throws Exception{
        one("provider_rejects_"+name,()->{
            NativeAppEvidence.Frame original=xml(source,"home");NativeAppEvidence.Node before=icon(original);
            List<NativeAppEvidence.Node> nodes=new ArrayList<NativeAppEvidence.Node>(original.nodes);nodes.remove(before);
            if(!"missing".equals(key))nodes.add(alter(before,key,value));
            NativeXiaomiProductPage.Page page=NativeXiaomiProductPage.inspectPreferredNavigation(GOAL,frame(nodes));
            yes(page.clickIds.isEmpty()&&page.editValues.isEmpty()&&page.quote==null,"no navigation from changed icon "+name);
        });
    }
    private static NativeActionSnapshotCheck.Snapshot mutate(NativeActionSnapshotCheck.Snapshot original,Mutation change){
        Map<String,Object> env=new TreeMap<String,Object>(original.env);
        Map<String,Map<String,Object>> rows=new TreeMap<String,Map<String,Object>>();
        for(NativeActionSnapshotCheck.Node n:original.nodes.values())rows.put(n.path,new TreeMap<String,Object>(n.v));
        change.apply(env,rows);List<NativeActionSnapshotCheck.Node> values=new ArrayList<NativeActionSnapshotCheck.Node>();
        for(Map<String,Object> n:rows.values())values.add(new NativeActionSnapshotCheck.Node(n));
        return new NativeActionSnapshotCheck.Snapshot(env,values);
    }
    private static void negative(String name,Mutation mutation)throws Exception{
        one("census_rejects_"+name,()->{
            NativeActionBridgeHost.IconCensus c=NativeActionBridgeHost.iconCensus(name,null);
            NativeActionSnapshotCheck.compare(c.intent,c.before,c.fresh,c.now);
            IntegrationChecks.rejects(()->NativeActionSnapshotCheck.compare(c.intent,c.before,mutate(c.fresh,mutation),c.now),
                    "same actual candidate must refuse "+name);
        });
    }
    private static void providerCases(Path source)throws Exception{
        one("provider_prefers_exact_icon_and_retains_legacy_contract",()->{
            NativeAppEvidence.Frame f=xml(source,"home");NativeXiaomiProductPage.Page current=NativeXiaomiProductPage.inspectPreferredNavigation(GOAL,f);
            NativeXiaomiProductPage.Page legacy=NativeXiaomiProductPage.inspect(GOAL,f);NativeAppEvidence.Node n=icon(f);
            yes(current.clickIds.equals(Collections.singleton(n.id))&&NativeXiaomiProductPage.SEARCH_ICON.equals(current.purposes.get(n.id)),"one actual stable icon with separate purpose");
            yes(current.searchIconNavigationCandidate&&"搜索".equals(n.label)&&current.quote==null&&current.editValues.isEmpty(),"navigation proposal only");
            yes(Boolean.FALSE.equals(current.evidence().get("navigation_semantics_device_verified"))&&Boolean.TRUE.equals(current.evidence().get("fresh_search_contract_required")),"unverified device semantics stated");
            yes(!legacy.clickIds.contains(n.id)&&legacy.clickIds.size()==1&&!legacy.searchIconNavigationCandidate,"old switcher contract retained");
            yes("open_search".equals(legacy.purposes.get(legacy.clickIds.iterator().next())),"old intent not renamed");
        });
        providerNegative(source,"missing","missing",null);
        providerNegative(source,"description","description","购买");
        providerNegative(source,"nonempty_text","text","促销");
        providerNegative(source,"different_label","label","查询商品");
        providerNegative(source,"class","class","android.widget.Button");
        providerNegative(source,"parent","parent","android.widget.FrameLayout");
        providerNegative(source,"overlap","bounds",new int[]{900,290,1156,372});
        providerNegative(source,"unclickable","clickable",Boolean.FALSE);
        providerNegative(source,"disabled","enabled",Boolean.FALSE);
        providerNegative(source,"password","password",Boolean.TRUE);
        providerNegative(source,"editable","editable",Boolean.TRUE);
        providerNegative(source,"scrollable","scrollable",Boolean.TRUE);
        providerNegative(source,"selected","selected",Boolean.TRUE);
        providerNegative(source,"checkable","checkable",Boolean.TRUE);
        providerNegative(source,"foreign_package","package","example.other");
        one("provider_rejects_duplicate",()->{
            NativeAppEvidence.Frame f=xml(source,"home");List<NativeAppEvidence.Node> nodes=new ArrayList<NativeAppEvidence.Node>(f.nodes);
            nodes.add(alter(alter(icon(f),"id","n999"),"path","0/99"));
            yes(NativeXiaomiProductPage.inspectPreferredNavigation(GOAL,frame(nodes)).clickIds.isEmpty(),"no first-match icon selection");
        });
        one("nonhome_contracts_remain_byte_value_equal",()->{
            for(String name:Arrays.asList("search-entry","suggestions","results","detail","home-promotion")){
                NativeAppEvidence.Frame f=xml(source,name);
                yes(NativeXiaomiProductPage.inspect(GOAL,f).evidence().equals(NativeXiaomiProductPage.inspectPreferredNavigation(GOAL,f).evidence()),"unchanged current contract "+name);
            }
        });
    }
    private static void censusCases()throws Exception{
        one("only_known_hint_literals_rotate_with_real_service_signatures",()->{
            NativeActionBridgeHost.IconCensus c=NativeActionBridgeHost.iconCensus("rotate","REDMI K系列电池换新");
            Map<String,Object> proof=NativeActionSnapshotCheck.compare(c.intent,c.before,c.fresh,c.now);
            yes(c.before.node("0/0/1").v.equals(c.fresh.node("0/0/1").v),"entire actual target unchanged");
            yes(c.before.node("0/0").v.equals(c.fresh.node("0/0").v),"actual ancestor unchanged");
            yes(new TreeSet<Object>((List<?>)proof.get("changed_paths")).equals(new TreeSet<Object>(Arrays.<Object>asList("0/0/0","0/0/0/0","0/0/0/0/0"))),"exact three changed hint records, nothing silently discarded");
            yes(Boolean.FALSE.equals(proof.get("grants_dispatch"))&&Boolean.FALSE.equals(proof.get("navigation_semantics_device_verified")),"predicate never grants effect or device qualification");
        });
        one("old_icon_intent_still_refused",()->{
            NativeActionBridgeHost.IconCensus c=NativeActionBridgeHost.iconCensus("legacy",null);
            NativeActionSnapshotCheck.Intent n=c.intent;
            NativeActionSnapshotCheck.Intent old=new NativeActionSnapshotCheck.Intent(NativeActionSnapshotCheck.SEARCH,n.pkg,n.path,n.label,n.refSha256,n.run,n.node,n.actionSha,n.historySha,n.identity,n.started,n.deadline);
            IntegrationChecks.rejects(()->NativeActionSnapshotCheck.compare(old,c.before,c.fresh,c.now),"legacy purpose never upgrades to icon permission");
        });
        negative("icon_description",(e,n)->n.get("0/0/1").put("description","other"));
        negative("icon_label",(e,n)->n.get("0/0/1").put("label","other"));
        negative("icon_reference",(e,n)->n.get("0/0/1").put("ref_signature_sha256",hash("FORGED_ICON")));
        negative("icon_geometry",(e,n)->n.get("0/0/1").put("bounds",Arrays.asList(1001,290,1156,372)));
        negative("icon_parent",(e,n)->n.get("0/0/1").put("parent_class","android.widget.FrameLayout"));
        negative("icon_removed",(e,n)->{n.remove("0/0/1");n.get("0/0").put("children",1);e.put("visited",n.size());});
        negative("icon_duplicate",(e,n)->n.get("0/2/0").put("view_id","com.xiaomi.shop.plugin.homepage:id/searchIcon"));
        for(String key:Arrays.asList("clickable","action_click","enabled")){
            final String field=key;negative("icon_"+field,(e,n)->n.get("0/0/1").put(field,false));
        }
        for(String key:Arrays.asList("editable","password","scrollable","focused","selected","checkable","checked")){
            final String field=key;negative("icon_"+field,(e,n)->n.get("0/0/1").put(field,true));
        }
        negative("ancestor_geometry",(e,n)->n.get("0/0").put("bounds",Arrays.asList(0,1,1224,400)));
        negative("ancestor_capability",(e,n)->n.get("0/0").put("scrollable",true));
        negative("home_role",(e,n)->n.get("0/1/0").put("selected",false));
        negative("hint_geometry",(e,n)->n.get("0/0/0/0/0").put("bounds",Arrays.asList(156,301,303,360)));
        negative("hint_clickable",(e,n)->n.get("0/0/0/0").put("clickable",true));
        negative("hint_editable",(e,n)->n.get("0/0/0/0/0").put("editable",true));
        negative("hint_other_resource",(e,n)->n.get("0/0/0/0/0").put("view_id","com.xiaomi.shop:id/other"));
        negative("hint_unpaired_description",(e,n)->n.get("0/0/0/0").put("description","搜索另一件商品"));
        negative("hint_forged_reference",(e,n)->n.get("0/0/0").put("ref_signature_sha256",hash("FORGED_HINT")));
        negative("hint_forged_label",(e,n)->n.get("0/0/0").put("label","搜索AX3000T"));
        negative("hint_added_descendant",(e,n)->{
            Map<String,Object> child=new TreeMap<String,Object>(n.get("0/0/0/0/0"));child.put("path","0/0/0/0/1");n.put("0/0/0/0/1",child);
            n.get("0/0/0/0").put("children",2);e.put("visited",n.size());
        });
        negative("foreign_node",(e,n)->n.get("0/0/0/0/0").put("package","example.other"));
        negative("new_overlay",(e,n)->n.get("0/2/0").put("bounds",Arrays.asList(1000,290,1156,372)));
        negative("display",(e,n)->e.put("display_id",16));
        negative("window",(e,n)->e.put("window_id",97));
        negative("reported_windows",(e,n)->e.put("reported_windows_sha256",hash("NEW_WINDOWS")));
        negative("installed_identity",(e,n)->e.put("installed_set_sha256",hash("NEW_UID_OR_APK")));
        negative("collection_omission",(e,n)->e.put("node_omissions",1));
        negative("unknown_field",(e,n)->n.get("0/0/0/0").put("future_capability",true));
        one("profile_full_uid_cannot_change",()->{
            NativeActionBridgeHost.IconCensus c=NativeActionBridgeHost.iconCensus("profile",null);
            Map<String,Object> profile=new TreeMap<String,Object>();profile.put("profile_target_sha256",hash("HOST_PROFILE"));
            profile.put("profile_user_id",10);profile.put("profile_user_serial",5L);profile.put("profile_full_uid",1010485);
            profile.put("profile_task_id",1000004);profile.put("profile_parent_task_id",1350);
            profile.put("profile_task_token_id","12345678-1234-4234-8234-123456789abc");
            NativeActionSnapshotCheck.Snapshot before=mutate(c.before,(e,n)->e.putAll(profile));
            NativeActionSnapshotCheck.Snapshot fresh=mutate(c.fresh,(e,n)->e.putAll(profile));
            Map<String,Object> identity=new TreeMap<String,Object>(c.intent.identity);identity.putAll(profile);
            NativeActionSnapshotCheck.Intent in=new NativeActionSnapshotCheck.Intent(c.intent.purpose,c.intent.pkg,c.intent.path,c.intent.label,c.intent.refSha256,c.intent.run,c.intent.node,c.intent.actionSha,c.intent.historySha,identity,c.intent.started,c.intent.deadline);
            NativeActionSnapshotCheck.compare(in,before,fresh,c.now);
            IntegrationChecks.rejects(()->NativeActionSnapshotCheck.compare(in,before,mutate(fresh,(e,n)->e.put("profile_full_uid",1010367)),c.now),"same package/display is not same full UID");
        });
    }
    static void run(Path source)throws Exception{
        NativeActionBridgeHost.sourceRoot=source;
        providerCases(source);censusCases();NativeActionBridgeHost.stableIconLiveCases();
        XiaomiActionGuardHost.stableIconSessionCases(source.resolve("tests/native-xiaomi-product/fixtures"));
    }
    public static void main(String[] args)throws Exception{
        run(Paths.get(args[0]));
        IntegrationChecks.finish(Paths.get(args[1]),"hepta.native-stable-search-icon-host.v1",
                "Production default Session and actual extracted Service methods; explicit host Android and identity doubles. Icon device semantics, model execution and phone business success are not verified.");
    }
}

