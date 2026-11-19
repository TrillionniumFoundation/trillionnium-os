package org.trillionnium.hepta.background;
import org.json.*;
import java.nio.charset.StandardCharsets;
public final class ControllerDisplayHandoffHostTest {
  interface Work {void run()throws Exception;}
  static int cases,assertions;
  static void ok(boolean value){assertions++;if(!value)throw new AssertionError("condition false");}
  static void test(String name,Work w)throws Exception{w.run();cases++;System.out.println("PASS "+name);}
  static void no(Work w)throws Exception{assertions++;try{w.run();}catch(java.io.IOException expected){return;}throw new AssertionError("invalid handoff accepted");}
  static final String OWNER=repeat('a',64),TASK=repeat('b',32),NONCE=repeat('c',32);
  static String repeat(char c,int count){StringBuilder b=new StringBuilder();while(count-->0)b.append(c);return b.toString();}
  static ControllerDisplayHandoff.Request request()throws Exception{return ControllerDisplayHandoff.request(
    ControllerDisplayHandoff.fromOwnerButton(10481,9667,46539304,1479,218,"Hepta public own-group probe-208797e1-5f3f-4f8e-b0a8-b3e631220caa",7040,1000,OWNER),
    TASK,NONCE,1500,481500,83,new JSONObject().put("source_path","/actual-test-only/base.apk").put("uid",10481));}
  static JSONObject display(int id,int group,int state)throws Exception{return new JSONObject().put("id",id).put("group",group)
    .put("state",state).put("type",id>1?5:1).put("flags",id>1?7040:0).put("name",id>1?"Hepta public own-group probe-208797e1-5f3f-4f8e-b0a8-b3e631220caa":"physical"+id)
    .put("unique_id","unique-"+id).put("owner_uid",0).put("owner_package",id>1?"com.android.shell":JSONObject.NULL);}
  static JSONObject sample(long started,boolean present)throws Exception{
    JSONArray displays=new JSONArray().put(display(0,0,2)).put(display(1,1,1));if(present)displays.put(display(218,2,2));
    JSONObject task=new JSONObject().put("id",1479).put("display",218).put("uid",10481).put("user",0).put("parent",-1)
      .put("token","synthetic-test-token").put("intent",ControllerDisplayHandoff.COMPONENT).put("real",ControllerDisplayHandoff.COMPONENT);
    return new JSONObject().put("schema",ControllerDisplayHandoff.SAMPLE).put("complete",true).put("started_elapsed_ms",started).put("finished_elapsed_ms",started+10)
      .put("app_uid",10481).put("app_pid",9667).put("app_start_ticks",46539304).put("displays",displays)
      .put("controller_task",present?task:JSONObject.NULL).put("controller_active_complete",present)
      .put("root_ids",new JSONArray(present?new int[]{11,1479}:new int[]{11}))
      .put("leaf_ids",new JSONArray(present?new int[]{12,1479}:new int[]{12}))
      .put("recent_ids",new JSONArray(present?new int[]{12,1479}:new int[]{12}))
      .put("physical",new JSONObject().put("0","physical0-complete-projection").put("1","physical1-complete-projection"))
      .put("foreign_history_sha256",repeat('d',64)).put("recents_raw_sha256",present?repeat('e',64):repeat('f',64));
  }
  static JSONObject before(ControllerDisplayHandoff.Request r)throws Exception{return ControllerDisplayHandoff.envelope(ControllerDisplayHandoff.BEFORE,r)
    .put("reader_uid",0).put("reader_pid",20000).put("reader_start_ticks",999).put("sample",sample(1510,true));}
  static JSONObject complete(ControllerDisplayHandoff.Request r,JSONObject b)throws Exception{return ControllerDisplayHandoff.envelope(ControllerDisplayHandoff.COMPLETE,r)
    .put("before_sha256",ControllerDisplayHandoff.sha(b.toString().getBytes(StandardCharsets.UTF_8)))
    .put("reader_pid",20000).put("reader_start_ticks",999).put("absence_samples",new JSONArray().put(sample(1800,false)).put(sample(2000,false)))
    .put("current_absence_verified",true).put("business_success",false);}
  static JSONObject cp(JSONObject v)throws Exception{return ControllerDisplayHandoff.copy(v);}
  public static void main(String[] args)throws Exception{
    final ControllerDisplayHandoff.Request r=request();final JSONObject b=before(r),c=complete(r,b);
    test("real request wire roundtrip binds exact fields",()->ok(ControllerDisplayHandoff.fromWire(r.wire()).requestSha.equals(r.requestSha)));
    test("before root census then two distinct absence samples",()->{ok(ControllerDisplayHandoff.validateBefore(b,r,1600,83).similar(b));ok(ControllerDisplayHandoff.validateComplete(c,b,r,2100,83).similar(c));});
    test("held display and task remain pending",()->ok(!ControllerDisplayHandoff.validateWaiting(sample(1700,true),b,r)));
    test("OFF settling display is pending not absence",()->{JSONObject s=sample(1700,true);s.getJSONArray("displays").getJSONObject(2).put("state",1);ok(!ControllerDisplayHandoff.validateWaiting(s,b,r));});
    test("UNKNOWN settling display is pending not absence",()->{JSONObject s=sample(1700,true);s.getJSONArray("displays").getJSONObject(2).put("state",0);ok(!ControllerDisplayHandoff.validateWaiting(s,b,r));});
    test("retained recent with no display/live task is pending",()->{JSONObject s=sample(1700,false);s.getJSONArray("recent_ids").put(1479);ok(!ControllerDisplayHandoff.validateWaiting(s,b,r));});
    test("first current absence alone grants no completion",()->{JSONObject x=cp(c);x.put("absence_samples",new JSONArray().put(sample(1800,false)));no(()->ControllerDisplayHandoff.validateComplete(x,b,r,2100,83));});
    test("duplicate identical after sample refuses",()->{JSONObject x=cp(c);x.put("absence_samples",new JSONArray().put(sample(1800,false)).put(sample(1800,false)));no(()->ControllerDisplayHandoff.validateComplete(x,b,r,2100,83));});
    test("before missing task in full census refuses",()->{JSONObject x=cp(b);x.getJSONObject("sample").put("leaf_ids",new JSONArray().put(12));no(()->ControllerDisplayHandoff.validateBefore(x,r,1600,83));});
    for(String key:new String[]{"root_ids","leaf_ids","recent_ids"})test("after lingering "+key+" refuses",()->{JSONObject x=cp(c);x.getJSONArray("absence_samples").getJSONObject(1).getJSONArray(key).put(1479);no(()->ControllerDisplayHandoff.validateComplete(x,b,r,2100,83));});
    test("off display is not an absence proof",()->{JSONObject x=cp(c);JSONObject s=x.getJSONArray("absence_samples").getJSONObject(1);s.getJSONArray("displays").put(display(218,2,1));no(()->ControllerDisplayHandoff.validateComplete(x,b,r,2100,83));});
    test("same task object remains not absence",()->{JSONObject x=cp(c);x.getJSONArray("absence_samples").getJSONObject(1).put("controller_task",b.getJSONObject("sample").getJSONObject("controller_task"));no(()->ControllerDisplayHandoff.validateComplete(x,b,r,2100,83));});
    for(String key:new String[]{"uid","pid","process_start_ticks","task_id","display_id","owner_sha256"})test("request locator mutation binds "+key,()->{JSONObject j=r.json();Object v=j.getJSONObject("locator").get(key);j.getJSONObject("locator").put(key,key.equals("owner_sha256")?repeat('0',64):((Number)v).longValue()+1);String wire=java.util.Base64.getEncoder().encodeToString(j.toString().getBytes(StandardCharsets.UTF_8));ControllerDisplayHandoff.Request other=ControllerDisplayHandoff.fromWire(wire);no(()->ControllerDisplayHandoff.validateBefore(b,other,1600,83));});
    test("integer overflow cannot alias old display",()->{JSONObject j=r.json();j.getJSONObject("locator").put("display_id",4294967514L);no(()->ControllerDisplayHandoff.fromWire(java.util.Base64.getEncoder().encodeToString(j.toString().getBytes(StandardCharsets.UTF_8))));});
    test("physical display locator refuses",()->no(()->ControllerDisplayHandoff.fromOwnerButton(10481,9667,46539304,1479,0,"physical",7040,1000,OWNER)));
    test("wrong flags locator refuses",()->no(()->ControllerDisplayHandoff.fromOwnerButton(10481,9667,46539304,1479,218,"other",0,1000,OWNER)));
    test("stale owner button locator refuses",()->no(()->ControllerDisplayHandoff.request(r.locator,TASK,NONCE,20000,480000,83,r.installation())));
    test("30s cap remains exact",()->{ok(r.deadline==31500);no(()->r.fence(31500,83));});
    test("task deadline shorter than30s is preserved",()->{ControllerDisplayHandoff.Request q=ControllerDisplayHandoff.request(r.locator,TASK,NONCE,1500,3000,83,r.installation());ok(q.deadline==3000);no(()->q.fence(3000,83));});
    test("clock reversal and wrong boot refuse",()->{no(()->r.fence(1499,83));no(()->r.fence(1600,84));});
    test("group collision refuses even with trusted flags",()->{JSONObject x=cp(b);x.getJSONObject("sample").getJSONArray("displays").put(display(219,2,2).put("name","other").put("unique_id","unique-219"));no(()->ControllerDisplayHandoff.validateBefore(x,r,1600,83));});
    test("foreign display joining group during wait refuses",()->{JSONObject s=sample(1700,true);s.getJSONArray("displays").put(display(219,2,2).put("name","other").put("unique_id","unique-219"));no(()->ControllerDisplayHandoff.validateWaiting(s,b,r));});
    test("physical shares group refuses",()->{JSONObject x=cp(b);x.getJSONObject("sample").getJSONArray("displays").getJSONObject(0).put("group",2);no(()->ControllerDisplayHandoff.validateBefore(x,r,1600,83));});
    test("disabled physical cover must still be enumerated",()->{JSONObject x=cp(b);x.getJSONObject("sample").getJSONArray("displays").remove(1);no(()->ControllerDisplayHandoff.validateBefore(x,r,1600,83));});
    test("duplicate direct display ID refuses",()->{JSONObject x=cp(b);x.getJSONObject("sample").getJSONArray("displays").put(display(218,2,2));no(()->ControllerDisplayHandoff.validateBefore(x,r,1600,83));});
    test("old caller display moved to new ID refuses",()->{JSONObject x=cp(c);x.getJSONArray("absence_samples").getJSONObject(0).getJSONArray("displays").put(display(220,3,2).put("unique_id","unique-218"));no(()->ControllerDisplayHandoff.validateComplete(x,b,r,2100,83));});
    test("root token identity changes while waiting refuses",()->{JSONObject s=sample(1700,true);s.getJSONObject("controller_task").put("token","different");no(()->ControllerDisplayHandoff.validateWaiting(s,b,r));});
    test("foreign history changes refuse both wait and completion",()->{JSONObject s=sample(1700,false).put("foreign_history_sha256",repeat('0',64));no(()->ControllerDisplayHandoff.validateWaiting(s,b,r));JSONObject x=cp(c);x.getJSONArray("absence_samples").getJSONObject(1).put("foreign_history_sha256",repeat('0',64));no(()->ControllerDisplayHandoff.validateComplete(x,b,r,2100,83));});
    test("physical focus projection changes refuse",()->{JSONObject x=cp(c);x.getJSONArray("absence_samples").getJSONObject(1).getJSONObject("physical").put("0","changed");no(()->ControllerDisplayHandoff.validateComplete(x,b,r,2100,83));});
    test("physical display state changes refuse",()->{JSONObject x=cp(c);x.getJSONArray("absence_samples").getJSONObject(1).getJSONArray("displays").getJSONObject(0).put("state",1);no(()->ControllerDisplayHandoff.validateComplete(x,b,r,2100,83));});
    test("unrelated recents raw can differ only with same protected projection",()->ok(ControllerDisplayHandoff.validateComplete(c,b,r,2100,83)!=null));
    test("PID reuse and boot generation refuse",()->{JSONObject x=cp(c);x.getJSONArray("absence_samples").getJSONObject(1).put("app_start_ticks",46539305);no(()->ControllerDisplayHandoff.validateComplete(x,b,r,2100,83));no(()->ControllerDisplayHandoff.validateComplete(c,b,r,2100,84));});
    test("another reader cannot finish before receipt",()->{JSONObject x=cp(c).put("reader_pid",20001);no(()->ControllerDisplayHandoff.validateComplete(x,b,r,2100,83));});
    test("modified before receipt cannot authorize continuation",()->{JSONObject x=cp(b).put("extra","changed");no(()->ControllerDisplayHandoff.validateComplete(c,x,r,2100,83));});
    test("business success claim refuses",()->{JSONObject x=cp(c).put("business_success",true);no(()->ControllerDisplayHandoff.validateComplete(x,b,r,2100,83));});
    test("mutable returned proof cannot mutate original",()->{JSONObject x=ControllerDisplayHandoff.validateBefore(b,r,1600,83);x.put("reader_pid",1);ok(b.getInt("reader_pid")==20000);});
    test("only exact bound caller removal is incomplete",()->{ok(ControllerDisplayHandoff.onlyCallerRemoved(new int[]{0,1,218},new int[]{1,0},218));ok(!ControllerDisplayHandoff.onlyCallerRemoved(new int[]{0,1,218},new int[]{0,1,218},218));});
    test("other deletion addition duplicate never becomes retry",()->{ok(!ControllerDisplayHandoff.onlyCallerRemoved(new int[]{0,1,218,220},new int[]{0,1,218},218));ok(!ControllerDisplayHandoff.onlyCallerRemoved(new int[]{0,1,218},new int[]{0,1,219},218));ok(!ControllerDisplayHandoff.onlyCallerRemoved(new int[]{0,1,218,218},new int[]{0,1,218},218));});
    System.out.println(new JSONObject().put("cases",cases).put("assertions",assertions).put("all_pass",true).put("phone_operations",0).put("synthetic_contract_tests",true));
  }
}
