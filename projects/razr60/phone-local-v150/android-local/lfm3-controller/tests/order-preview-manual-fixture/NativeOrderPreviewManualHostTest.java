package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import org.json.JSONObject;

/** Protocol fixtures are explicitly synthetic. No SKU, route, Android effect,
 * model output, Phone observation, save, checkout or business success is proved. */
public final class NativeOrderPreviewManualHostTest {
    private interface Checked {void run()throws Exception;}
    private static int assertions;
    private static final List<Object> results=new ArrayList<Object>();
    private static String h(char value){char[] x=new char[64];Arrays.fill(x,value);return new String(x);}
    private static String id(char value){return h(value).substring(0,32);}
    private static final String OWNER="测试采集订单预览[preview_open_sku]：在小米商城准备购买1台AX3000T，预算不超过200元，核对商品、数量和总额后停在订单确认页，不提交订单、不支付。";
    private static void check(boolean value,String reason){assertions++;if(!value)throw new AssertionError(reason);}
    private static void rejects(Checked checked,String message)throws Exception{
        boolean refused=false;
        try{checked.run();}catch(Exception failure){
            refused=true;check(failure.getMessage()!=null&&failure.getMessage().contains(message),"unexpected refusal: "+failure);
        }
        check(refused,"expected refusal: "+message);
    }
    private static void run(String name,Checked body)throws Exception{
        int before=assertions;Map<String,Object> result=new TreeMap<String,Object>();result.put("name",name);
        try{body.run();result.put("pass",true);}
        catch(Exception|Error failure){result.put("pass",false);result.put("error",failure.toString());throw failure;}
        finally{result.put("assertions",Integer.valueOf(assertions-before));results.add(result);}
    }
    private static final class Fixture {
        final NativeOrderPreviewManual.Owner owner;
        final NativeActionSnapshotCheck.Snapshot census;
        final Map<String,Object> binding;
        final NativeOrderPreviewManual.Ready ready;
        Fixture()throws Exception{
            owner=NativeOrderPreviewManual.recognize(NativeAppGoal.parse(OWNER,NativeAppGoal.XIAOMI_PACKAGE));
            check(owner!=null,"explicit fixture owner recognized");
            Map<String,Object> env=new TreeMap<String,Object>();
            env.put("task_id",id('a'));env.put("owner_sha256",owner.goal.ownerSha256);env.put("target_sha256",h('b'));
            env.put("authorization_sha256",h('c'));env.put("selection_sha256",h('d'));env.put("installed_set_sha256",h('e'));
            env.put("goal_sha256",owner.goal.contractSha256);env.put("background_generation","11111111-2222-3333-4444-555555555555");
            env.put("origin_observation_id",id('f'));env.put("package","com.xiaomi.shop");env.put("display_id",Integer.valueOf(7));
            env.put("window_id",Integer.valueOf(8));env.put("rotation",Integer.valueOf(0));env.put("width",Integer.valueOf(720));
            env.put("height",Integer.valueOf(1280));env.put("root_bounds",Arrays.asList(0,0,720,1280));
            env.put("window_metadata_sha256",h('1'));env.put("reported_windows_sha256",h('2'));
            env.put("reported_windows_complete",true);env.put("ime_visibility","hidden");env.put("captured_elapsed_ms",Long.valueOf(100));
            env.put("full_native_complete",true);env.put("visited",Integer.valueOf(2));env.put("pending",Integer.valueOf(0));
            env.put("node_omissions",Integer.valueOf(0));env.put("text_omissions",Integer.valueOf(0));env.put("child_omissions",Integer.valueOf(0));
            env.put("profile_target_sha256",h('3'));env.put("profile_user_id",Integer.valueOf(10));
            env.put("profile_user_serial",Long.valueOf(11));env.put("profile_full_uid",Integer.valueOf(1012345));
            env.put("profile_task_id",Integer.valueOf(12));env.put("profile_parent_task_id",Integer.valueOf(13));
            env.put("profile_task_token_id","aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
            Map<String,Object> node=new TreeMap<String,Object>();
            node.put("path","0");node.put("parent_class","");node.put("package","com.xiaomi.shop");node.put("window_id",Integer.valueOf(8));
            node.put("class","android.widget.FrameLayout");node.put("view_id","synthetic.protocol.only");
            node.put("text","Synthetic protocol node; not a SKU selector");node.put("description","");node.put("label",null);
            node.put("ref_signature_sha256",null);node.put("bounds",Arrays.asList(0,0,720,1280));
            for(String key:Arrays.asList("visible","enabled","clickable","action_click"))node.put(key,true);
            for(String key:Arrays.asList("editable","scrollable","focused","password","selected","checkable","checked"))node.put(key,false);
            node.put("children",Integer.valueOf(1));node.put("scroll_actions","");node.put("ime_enter","");node.put("input_sha256",null);
            node.put("clickable",false);node.put("action_click",false);
            Map<String,Object> child=new TreeMap<String,Object>(node);child.put("path","0/0");
            child.put("parent_class","android.widget.FrameLayout");child.put("class","android.widget.Button");
            child.put("children",Integer.valueOf(0));child.put("label","synthetic-protocol-node");
            child.put("ref_signature_sha256",h('a'));child.put("clickable",true);child.put("action_click",true);
            census=new NativeActionSnapshotCheck.Snapshot(env,Arrays.asList(new NativeActionSnapshotCheck.Node(node),new NativeActionSnapshotCheck.Node(child)));
            binding=new TreeMap<String,Object>();
            for(String key:NativeActionSnapshotCheck.PROFILE_AUTHORITY)if(!"origin_observation_id".equals(key))binding.put(key,env.get(key));
            binding.put("controller_build_identity_sha256",h('4'));
            ready=newReady(census,binding,200,50000,60000);
        }
        NativeOrderPreviewManual.Ready newReady(NativeActionSnapshotCheck.Snapshot value,Map<String,Object> identity,long now,long task,long lease){
            List<NativeOrderPreviewManual.Artifact> refs=Arrays.asList(
                new NativeOrderPreviewManual.Artifact("before-census.json",10,h('5')),
                new NativeOrderPreviewManual.Artifact("before-frame.json",10,h('6')),
                new NativeOrderPreviewManual.Artifact("before.png",10,h('7')));
            return new NativeOrderPreviewManual.Ready(owner,value,identity,refs,id('8'),h('9'),now,task,lease);
        }
        Map<String,Object> request(){
            Map<String,Object> node=new TreeMap<String,Object>();node.put("tree_path","0/0");
            node.put("facts_sha256",NativeOrderPreviewManual.nodeFacts(census.node("0/0")));
            Map<String,Object> request=new TreeMap<String,Object>();request.put("schema",NativeOrderPreviewManual.REQUEST_SCHEMA);
            request.put("request_id",id('0'));request.put("task_id",ready.taskId);request.put("owner_sha256",owner.goal.ownerSha256);
            request.put("ready_sha256",ready.sha256);request.put("nonce",ready.nonce);request.put("purpose",owner.purpose);request.put("node",node);
            return request;
        }
        NativeOrderPreviewManual.Request parsed(Map<String,Object> request)throws Exception{
            return NativeOrderPreviewManual.Request.parse(NativeOrderPreviewManual.json(request));
        }
    }
    private static void requestMismatch(final String field,final Object replacement)throws Exception{
        final Fixture f=new Fixture();Map<String,Object> value=f.request();value.put(field,replacement);
        final NativeOrderPreviewManual.Request request=f.parsed(value);
        rejects(new Checked(){public void run(){f.ready.consume(request,300);}},"request does not name this live READY");
    }
    public static void main(String[] args)throws Exception{
        final Path output=Paths.get(args[0]);boolean passed=false;
        try{
            run("explicit_manual_owner_is_separate_from_normal_preview",new Checked(){public void run(){
                NativeAppGoal normal=NativeAppGoal.parse(OWNER.substring(OWNER.indexOf("：")+1),NativeAppGoal.XIAOMI_PACKAGE);
                NativeAppGoal manual=NativeAppGoal.parse(OWNER,NativeAppGoal.XIAOMI_PACKAGE);
                check(normal!=null&&manual!=null,"both literal goals");check(NativeOrderPreviewManual.recognize(normal)==null,"normal owner not manual");
                check(!normal.ownerSha256.equals(manual.ownerSha256)&&!normal.contractSha256.equals(manual.contractSha256),"separate owner/contract");
                check(manual.toolCeiling.equals(normal.toolCeiling)&&!manual.toolCeiling.contains("submit"),"old tool ceiling not widened");
            }});
            run("unknown_purpose_and_wrong_selected_package_refuse",new Checked(){public void run(){
                check(NativeAppGoal.parse(OWNER.replace("preview_open_sku","submit_order"),NativeAppGoal.XIAOMI_PACKAGE)==null,"unknown purpose");
                check(NativeAppGoal.parse(OWNER,NativeAppGoal.CTRIP_PACKAGE)==null,"wrong explicit App");
            }});
            run("quantity_two_or_extra_clause_is_not_a_fixture_owner",new Checked(){public void run(){
                check(NativeAppGoal.parse(OWNER.replace("1台","2台"),NativeAppGoal.XIAOMI_PACKAGE)==null,"two quantities");
                check(NativeAppGoal.parse(OWNER+"然后支付。",NativeAppGoal.XIAOMI_PACKAGE)==null,"extra instruction");
            }});
            run("synthetic_complete_request_only_produces_unbound_refusal",new Checked(){public void run()throws Exception{
                Fixture f=new Fixture();NativeOrderPreviewManual.ManualPreviewGuard guard=f.ready.consume(f.parsed(f.request()),300);
                Map<String,Object> result=guard.refuseUnbound(301);
                for(String key:Arrays.asList("model_proposal_created","dispatch_claimed","platform_call_entered","effect","business_success","order_submitted","payment_attempted"))
                    check(Boolean.FALSE.equals(result.get(key)),key+" remains false");
                check("page_navigation_route_unbound".equals(result.get("reason")),"unbound reason");
            }});
            run("ready_keeps_original_task_lease_and_fixed_review_bounds",new Checked(){public void run()throws Exception{
                Fixture f=new Fixture();check(f.ready.reviewDeadline==30200,"fixed 30-second review");
                check(f.newReady(f.census,f.binding,200,900,1000).reviewDeadline==900,"task clamps review");
                check(f.newReady(f.census,f.binding,200,1000,800).reviewDeadline==800,"lease clamps review");
            }});
            run("full_census_nullable_fields_are_preserved",new Checked(){public void run()throws Exception{
                Fixture f=new Fixture();JSONObject root=new JSONObject(new String(NativeOrderPreviewManual.json(NativeOrderPreviewManual.censusEvidence(f.census)),StandardCharsets.UTF_8));
                JSONObject n=root.getJSONArray("nodes").getJSONObject(0);
                check(n.has("label")&&n.isNull("label")&&n.has("ref_signature_sha256")&&n.isNull("ref_signature_sha256")
                        &&n.has("input_sha256")&&n.isNull("input_sha256"),"complete nullable node fields");
                check(n.length()==NativeActionSnapshotCheck.NK.size(),"no node fields lost");
            }});
            run("wrong_task_refuses",new Checked(){public void run()throws Exception{requestMismatch("task_id",id('b'));}});
            run("wrong_owner_refuses",new Checked(){public void run()throws Exception{requestMismatch("owner_sha256",h('b'));}});
            run("wrong_ready_refuses",new Checked(){public void run()throws Exception{requestMismatch("ready_sha256",h('b'));}});
            run("wrong_nonce_refuses",new Checked(){public void run()throws Exception{requestMismatch("nonce",h('b'));}});
            run("different_known_purpose_refuses",new Checked(){public void run()throws Exception{requestMismatch("purpose","preview_open_confirmation");}});
            run("unknown_request_field_refuses",new Checked(){public void run()throws Exception{
                final Fixture f=new Fixture();final Map<String,Object> value=f.request();value.put("coordinates",Arrays.asList(3,4));
                rejects(new Checked(){public void run()throws Exception{f.parsed(value);}},"exact JSON keys");
            }});
            run("duplicate_request_key_refuses",new Checked(){public void run()throws Exception{
                Fixture f=new Fixture();String valid=new String(NativeOrderPreviewManual.json(f.request()),StandardCharsets.UTF_8);
                final byte[] duplicate=("{\"schema\":\""+NativeOrderPreviewManual.REQUEST_SCHEMA+"\","+valid.substring(1)).getBytes(StandardCharsets.UTF_8);
                rejects(new Checked(){public void run()throws Exception{NativeOrderPreviewManual.Request.parse(duplicate);}},"duplicate JSON key");
            }});
            run("malformed_utf8_refuses",new Checked(){public void run()throws Exception{
                boolean rejected=false;try{NativeOrderPreviewManual.Request.parse(new byte[]{(byte)0xc3,(byte)0x28});}
                catch(java.nio.charset.CharacterCodingException expected){rejected=true;}check(rejected,"strict UTF-8");
            }});
            run("wrong_node_hash_refuses",new Checked(){public void run()throws Exception{
                final Fixture f=new Fixture();Map<String,Object> value=f.request();Map<String,Object> node=new TreeMap<String,Object>();
                node.put("tree_path","0/0");node.put("facts_sha256",h('b'));value.put("node",node);
                final NativeOrderPreviewManual.Request parsed=f.parsed(value);
                rejects(new Checked(){public void run(){f.ready.consume(parsed,300);}},"node facts differ");
            }});
            run("missing_node_refuses",new Checked(){public void run()throws Exception{
                final Fixture f=new Fixture();Map<String,Object> value=f.request();Map<String,Object> node=new TreeMap<String,Object>();
                node.put("tree_path","0/9");node.put("facts_sha256",h('b'));value.put("node",node);
                final NativeOrderPreviewManual.Request parsed=f.parsed(value);
                rejects(new Checked(){public void run(){f.ready.consume(parsed,300);}},"missing path");
            }});
            run("review_deadline_is_exclusive",new Checked(){public void run()throws Exception{
                final Fixture f=new Fixture();final NativeOrderPreviewManual.Request request=f.parsed(f.request());
                rejects(new Checked(){public void run(){f.ready.consume(request,f.ready.reviewDeadline);}},"expired");
            }});
            run("backward_clock_refuses",new Checked(){public void run()throws Exception{
                final Fixture f=new Fixture();final NativeOrderPreviewManual.Request request=f.parsed(f.request());
                rejects(new Checked(){public void run(){f.ready.consume(request,199);}},"clock moved backwards");
            }});
            run("second_request_cannot_reuse_ready",new Checked(){public void run()throws Exception{
                final Fixture f=new Fixture();final NativeOrderPreviewManual.Request request=f.parsed(f.request());f.ready.consume(request,300);
                rejects(new Checked(){public void run(){f.ready.consume(request,301);}},"already consumed");
            }});
            run("second_refusal_cannot_reuse_guard",new Checked(){public void run()throws Exception{
                Fixture f=new Fixture();final NativeOrderPreviewManual.ManualPreviewGuard guard=f.ready.consume(f.parsed(f.request()),300);
                guard.refuseUnbound(301);rejects(new Checked(){public void run(){guard.refuseUnbound(302);}},"already reported");
            }});
            run("incomplete_census_refuses_before_ready",new Checked(){public void run()throws Exception{
                Fixture f=new Fixture();final Map<String,Object> env=new TreeMap<String,Object>(f.census.env);env.put("pending",Integer.valueOf(1));
                final List<NativeActionSnapshotCheck.Node> nodes=new ArrayList<NativeActionSnapshotCheck.Node>(f.census.nodes.values());
                rejects(new Checked(){public void run(){new NativeActionSnapshotCheck.Snapshot(env,nodes);}},"collection omitted");
            }});
            run("physical_display_refuses_ready",new Checked(){public void run()throws Exception{
                final Fixture f=new Fixture();Map<String,Object> env=new TreeMap<String,Object>(f.census.env);env.put("display_id",Integer.valueOf(1));
                final NativeActionSnapshotCheck.Snapshot physical=new NativeActionSnapshotCheck.Snapshot(env,new ArrayList<NativeActionSnapshotCheck.Node>(f.census.nodes.values()));
                rejects(new Checked(){public void run(){f.newReady(physical,f.binding,200,50000,60000);}},"managed-profile Xiaomi census");
            }});
            run("foreign_binding_refuses_ready",new Checked(){public void run()throws Exception{
                final Fixture f=new Fixture();final Map<String,Object> binding=new TreeMap<String,Object>(f.binding);binding.put("profile_full_uid",Integer.valueOf(1012346));
                rejects(new Checked(){public void run(){f.newReady(f.census,binding,200,50000,60000);}},"READY binding differs");
            }});
            run("guard_has_no_model_action_or_dispatch_api",new Checked(){public void run(){
                for(java.lang.reflect.Method method:NativeOrderPreviewManual.ManualPreviewGuard.class.getDeclaredMethods())
                    if(!method.isSynthetic())check(method.getName().equals("refuseUnbound"),"no action/permit/claim method: "+method);
                boolean originalPrivate=false;
                for(java.lang.reflect.Constructor<?> ctor:NativeOrderPreviewManual.ManualPreviewGuard.class.getDeclaredConstructors()){
                    if(!ctor.isSynthetic()){check(java.lang.reflect.Modifier.isPrivate(ctor.getModifiers()),"private guard constructor");originalPrivate=true;}
                }
                check(originalPrivate,"original private constructor exists");
            }});
            run("ordinary_packaged_asset_does_not_require_restricted_scope",new Checked(){public void run()throws Exception{
                byte[] raw=("{\"schema\":\"hepta.actual-build-inputs.v1\",\"version_code\":1,"
                        +"\"source_inputs\":[{\"synthetic\":\"protocol-only-not-a-phone-build\"}]}").getBytes(StandardCharsets.UTF_8);
                String actual=NativeOrderPreviewManual.packagedBuildSha(new java.io.ByteArrayInputStream(raw),null);
                check(actual.equals(NativeOrderPreviewManual.sha256(raw)),"ordinary scope records exact stream bytes");
                check(actual.equals(NativeOrderPreviewManual.packagedBuildSha(new java.io.ByteArrayInputStream(raw),actual)),
                        "existing restricted build pin remains binding");
                Fixture f=new Fixture();Map<String,Object> binding=new TreeMap<String,Object>(f.binding);
                binding.put("controller_build_identity_sha256",actual);
                NativeOrderPreviewManual.Ready ready=f.newReady(f.census,binding,200,50000,60000);
                check(actual.equals(ready.binding.get("controller_build_identity_sha256")),"actual asset digest retained in READY");
                final byte[] captured=raw;
                rejects(new Checked(){public void run()throws Exception{
                    NativeOrderPreviewManual.packagedBuildSha(new java.io.ByteArrayInputStream(captured),h('0'));
                }},"differs from captured scope");
                rejects(new Checked(){public void run()throws Exception{
                    NativeOrderPreviewManual.packagedBuildSha(new java.io.ByteArrayInputStream(captured),"invalid");
                }},"differs from captured scope");
            }});
            run("packaged_asset_missing_io_and_byte_bounds_refuse",new Checked(){public void run()throws Exception{
                rejects(new Checked(){public void run()throws Exception{
                    NativeOrderPreviewManual.packagedBuildSha(null,null);
                }},"unavailable");
                rejects(new Checked(){public void run()throws Exception{
                    NativeOrderPreviewManual.packagedBuildSha(new java.io.ByteArrayInputStream(new byte[0]),null);
                }},"is empty");
                rejects(new Checked(){public void run()throws Exception{
                    NativeOrderPreviewManual.packagedBuildSha(new java.io.ByteArrayInputStream(new byte[131073]),null);
                }},"byte bound");
                rejects(new Checked(){public void run()throws Exception{
                    NativeOrderPreviewManual.packagedBuildSha(new java.io.InputStream(){
                        public int read()throws java.io.IOException{throw new java.io.IOException("synthetic packaged asset IO failure");}
                    },null);
                }},"synthetic packaged asset IO failure");
                rejects(new Checked(){public void run()throws Exception{
                    NativeOrderPreviewManual.packagedBuildSha(new java.io.InputStream(){
                        public int read(){return 0;}
                        public int read(byte[] b,int off,int length){return 0;}
                    },null);
                }},"no read progress");
            }});
            run("packaged_asset_schema_and_original_bytes_are_required",new Checked(){public void run()throws Exception{
                for(final String raw:Arrays.asList(
                        "{\"schema\":\"wrong\",\"version_code\":1,\"source_inputs\":[{}]}",
                        "{\"schema\":\"hepta.actual-build-inputs.v1\",\"version_code\":0,\"source_inputs\":[{}]}",
                        "{\"schema\":\"hepta.actual-build-inputs.v1\",\"version_code\":1,\"source_inputs\":[]}",
                        "{\"schema\":\"hepta.actual-build-inputs.v1\",\"version_code\":1,\"source_inputs\":{}}")) {
                    rejects(new Checked(){public void run()throws Exception{
                        NativeOrderPreviewManual.packagedBuildSha(new java.io.ByteArrayInputStream(raw.getBytes(StandardCharsets.UTF_8)),null);
                    }},"contract differs");
                }
                boolean malformed=false;
                try{NativeOrderPreviewManual.packagedBuildSha(new java.io.ByteArrayInputStream(
                        "{\"schema\":".getBytes(StandardCharsets.UTF_8)),null);}catch(Exception failure){malformed=true;}
                check(malformed,"incomplete JSON cannot identify a build");
                boolean utf8=false;
                try{NativeOrderPreviewManual.packagedBuildSha(new java.io.ByteArrayInputStream(new byte[]{(byte)0xc3,0x28}),null);}
                catch(java.nio.charset.CharacterCodingException failure){utf8=true;}
                check(utf8,"invalid UTF-8 cannot identify a build");
            }});
            passed=true;
        }finally{
            Map<String,Object> report=new TreeMap<String,Object>();report.put("schema","hepta.order-preview.manual-fixture-host-cases.v1");
            report.put("all_pass",passed);report.put("cases",Integer.valueOf(results.size()));report.put("assertions",Integer.valueOf(assertions));
            report.put("results",results);report.put("fixture_scope","Synthetic protocol values; no real page, route, model or Android effect proof");
            report.put("page_route_bound",false);report.put("phone_execution",false);report.put("platform_call_entered",false);
            report.put("business_success",false);Files.write(output,NativeOrderPreviewManual.json(report));
        }
    }
}
