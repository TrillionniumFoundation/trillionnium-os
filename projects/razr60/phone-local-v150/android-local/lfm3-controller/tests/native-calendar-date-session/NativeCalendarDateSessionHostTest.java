package org.trillionnium.hepta.local;

import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import javax.imageio.ImageIO;
import org.json.JSONObject;
import org.trillionnium.hepta.background.ProfileTarget;
import org.trillionnium.hepta.background.WindowOwnership;

/** Actual pure Session/Goal/Gate/Domain/grammar/parser/private-file execution.
 * AX, installation query, clock, profile-window origin and Currentness are
 * explicit host ports. No actual model receipt or platform permit is produced. */
public final class NativeCalendarDateSessionHostTest {
    static final long START=1000000L;
    static final String OWNER="在携程查询2026年11月25日北京到上海的单程机票，1名成人";
    static final String TASK="55555555555555555555555555555555",GEN="11111111-1111-4111-8111-111111111111",TOKEN="22222222-2222-4222-8222-222222222222";
    static Path out,work;static byte[] png;static int assertions;
    static final List<Map<String,Object>> cases=new ArrayList<Map<String,Object>>();
    interface Work{void run()throws Exception;}
    static void check(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
    static void reject(Work work)throws Exception{boolean refused=false;try{work.run();}
        catch(IllegalArgumentException|IllegalStateException|IOException|ActionDecision.InvalidActionException expected){refused=true;}
        check(refused,"required rejection missing");}
    static void one(String name,Work work){Map<String,Object> result=new LinkedHashMap<String,Object>();result.put("name",name);int before=assertions;
        try{work.run();result.put("passed",true);}catch(Throwable failure){result.put("passed",false);result.put("error",failure.toString());
            java.io.StringWriter trace=new java.io.StringWriter();failure.printStackTrace(new java.io.PrintWriter(trace));result.put("stack",trace.toString());}
        result.put("assertions",assertions-before);cases.add(result);}
    static String id(){return UUID.randomUUID().toString().replace("-","");}static String hash(String value){return NativeAppEvidence.hash(value);}
    static final class Clock implements NativeCalendarDateProtocol.Clock{long now=START+210;public long elapsedRealtime(){return now;}}
    static final class ModelPort implements LocalInference{
        LocalRuntimeConfig config;int calls;boolean images=true,dispatch=true;
        ModelPort(LocalRuntimeConfig c){config=c;}
        public LocalRuntimeConfig configuration(){return config;}
        public boolean acceptsObservedImage(){return images;}
        public boolean modelOutputDispatchAllowed(){return dispatch&&!config.visualObservationOnly;}
        public Handle generate(String prompt,String system,File image,DecisionGrammar grammar,int max,long timeout,Callback callback){
            calls++;throw new AssertionError("host Offer gate must never call a model");}
    }
    static LocalRuntimeConfig gui(){return new LocalRuntimeConfig(ModelProfile.GUI_OWL_4B,"npu",8192,4,false);}
    static final class Env{
        final String owner;final ProfileTarget profile;final BackgroundSession.Selection selected;final TaskAuthorization auth;
        final TaskAuthorization.Gate gate;final NativeAppGoal goal;final NativeAppSession session;
        final Clock clock=new Clock();final ModelPort model=new ModelPort(gui());final Path directory,image;
        final List<String> journalLeaves=new ArrayList<String>();
        NativeCalendarDateEnvelope envelope;NativeAppEvidence.Frame calendarFrame;boolean live=true,installation=true,failOfferJournal;
        int installationChecks;
        Env()throws Exception{this(OWNER);}
        Env(String owner)throws Exception{
            this.owner=owner;profile=NativeProfileIdentityHostTest.ctrip();selected=NativeProfileIdentityHostTest.selection(owner,profile);
            auth=TaskAuthorization.parse(owner).forExecutionSelection(selected);gate=auth.bind(TASK);goal=selected.taskTarget.nativeGoal;
            directory=Files.createTempDirectory(work,"session-");image=directory.resolve("calendar.png");privateWrite(image,png);
            session=new NativeAppSession(TASK,gate,selected,new NativeAppEvidence.Installed(profile),hash("selection"),GEN,15,
                ()->{installationChecks++;if(!installation)throw new IllegalStateException("explicit host installation changed");},
                (leaf,value)->{if(failOfferJournal&&"native-calendar-date-offer.json".equals(leaf))throw new IOException("explicit journal failure");
                    journalLeaves.add(leaf);privateWrite(directory.resolve(leaf),new JSONObject(value).toString().getBytes(StandardCharsets.UTF_8));});
            NativeAppEvidence.Frame form=frame(formNodes(),START,id());session.observed(form);
            NativeAppDomain domain=session.domain();check(domain.clickIds.size()==1,"actual prequery date inspection domain");
            String node=domain.clickIds.iterator().next();ActionDecision action=action(form,"click",null,node);
            String run=id();session.beforeModelAction(1,action,run,START+50);
            // Explicit host Android/action receipt boundary; no platform dispatch was run.
            session.modelActionOutcome(action,run,true,true,false,hash("synthetic-year-action"),START+100);
            calendarFrame=frame(calendarNodes(),START+200,id());session.observed(calendarFrame);
            check(NativeCtripFlightPage.CALENDAR.equals(session.domain().phase),"actual inspected CALENDAR transition");
            envelope=envelope(calendarFrame);
        }
        NativeAppEvidence.Frame frame(List<NativeAppEvidence.Node> nodes,long captured,String observation){
            WindowOwnership window=new WindowOwnership(profile,GEN,15,96,1234,1200,TOKEN,UUID.randomUUID().toString(),
                    profile.profile.userId,profile.profile.serial,profile.fullUid,captured,captured+8000);
            return new NativeAppEvidence.Frame(TASK,goal.ownerSha256,selected.taskTarget.targetSha256,auth.sha256,hash("selection"),
                    observation,NativeAppGoal.CTRIP_PACKAGE,GEN,hash("tree-"+observation),hash("state-"+observation),MobiMindContract.sha(png),
                    hash("record-"+observation),hash("completion-"+observation),15,96,0,1224,2992,0,0,1224,2992,captured,false,true,nodes,1,true,window);
        }
        NativeCalendarDateEnvelope envelope(NativeAppEvidence.Frame facts)throws Exception{
            LocalInference.CurrentFrame current=new LocalInference.CurrentFrame(image.toFile(),TASK,goal.ownerSha256,facts.observationId,GEN,
                    NativeAppGoal.CTRIP_PACKAGE,MobiMindContract.sha(png),1224,2992,15,96,0,facts.capturedElapsedMs,
                    owner.getBytes(StandardCharsets.UTF_8),()->{if(!live)throw new IllegalStateException("explicit host currentness retired");});
            return NativeCalendarDateEnvelope.capture(goal,facts,current,profile,gui(),clock);
        }
        NativeAppSession.CalendarOffer offer()throws Exception{return session.offerCalendarDate(envelope,model,clock,START+30000);}
    }
    static void privateWrite(Path path,byte[] bytes)throws Exception{
        Files.write(path,bytes,StandardOpenOption.CREATE_NEW,StandardOpenOption.WRITE);
        Files.setPosixFilePermissions(path,PosixFilePermissions.fromString("rw-------"));
    }
    static NativeAppEvidence.Node node(String id,String path,String cls,String parent,String view,String text,int l,int t,int r,int b,boolean scroll){
        return new NativeAppEvidence.Node(id,NativeAppGoal.CTRIP_PACKAGE,cls,view,text,"",path,parent,hash("ref-"+path),text,l,t,r,b,
                true,false,false,false,scroll,false,false,false,scroll?Collections.singleton("down"):Collections.<String>emptySet());}
    static List<NativeAppEvidence.Node> calendarNodes(){List<NativeAppEvidence.Node> n=new ArrayList<NativeAppEvidence.Node>();
        n.add(node("n1","0","android.widget.FrameLayout","","","",0,0,1224,2992,false));
        n.add(node("n2","0/0","android.widget.ListView","android.widget.FrameLayout","ctrip.android.view:id/calendar_list","",50,200,1174,2400,true));
        n.add(node("n3","0/0/0","android.widget.LinearLayout","android.widget.ListView","","",50,200,1174,1800,false));
        n.add(node("n4","0/0/0/0","android.widget.LinearLayout","android.widget.LinearLayout","","",50,200,1174,260,false));
        n.add(node("n5","0/0/0/0/0","android.widget.TextView","android.widget.LinearLayout","ctrip.android.view:id/calendar_month_title_left_tv","2026年11月",50,200,1174,260,false));
        n.add(node("n6","0/0/1","android.widget.LinearLayout","android.widget.ListView","","",50,1900,1174,2400,false));
        n.add(node("n7","0/0/1/0","android.widget.LinearLayout","android.widget.LinearLayout","","",50,1900,1174,1960,false));
        n.add(node("n8","0/0/1/0/0","android.widget.TextView","android.widget.LinearLayout","ctrip.android.view:id/calendar_month_title_left_tv","2026年12月",50,1900,1174,1960,false));return n;}
    static List<NativeAppEvidence.Node> formNodes(){
        NativeActionSnapshotCheckHostTest.Fixture f=NativeActionSnapshotCheckHostTest.form(NativeActionSnapshotCheck.YEAR);
        f.nodes.get("0/0/2/5").put("text","11月22日周日");f.nodes.get("0/0/2/5").put("label","11月22日周日");
        List<NativeAppEvidence.Node> nodes=new ArrayList<NativeAppEvidence.Node>();int index=1;
        for(Map<String,Object> v:f.nodes.values()){List<?> b=(List<?>)v.get("bounds");nodes.add(new NativeAppEvidence.Node("n"+(index++),NativeAppGoal.CTRIP_PACKAGE,
            (String)v.get("class"),(String)v.get("view_id"),(String)v.get("text"),(String)v.get("description"),(String)v.get("path"),(String)v.get("parent_class"),
            (String)v.get("ref_signature_sha256"),(String)v.get("label"),(Integer)b.get(0),(Integer)b.get(1),(Integer)b.get(2),(Integer)b.get(3),
            (Boolean)v.get("enabled"),(Boolean)v.get("password"),(Boolean)v.get("clickable"),(Boolean)v.get("editable"),(Boolean)v.get("scrollable"),
            (Boolean)v.get("selected"),(Boolean)v.get("checkable"),(Boolean)v.get("checked"),Collections.<String>emptySet()));}return nodes;}
    static ActionDecision action(NativeAppEvidence.Frame frame,String action,String status,String node)throws Exception{
        JSONObject j=new JSONObject();j.put("reason","明确宿主动作边界");j.put("action",action);j.put("observation_id",frame.observationId);j.put("package",frame.packageName);
        if(node!=null){j.put("node_id",node);j.put("node_label",frame.byId.get(node).label);}if("wait".equals(action))j.put("duration_ms",400);if(status!=null){j.put("status",status);j.put("summary","宿主模拟未完成日期选择");}
        return ActionDecision.parse(j.toString());}
    static String raw(NativeCalendarDateEnvelope e)throws Exception{
        JSONObject j=new JSONObject();j.put("reason","选择目标日期");j.put("action",NativeCalendarDateIntent.ACTION);j.put("observation_id",e.facts.observationId);
        j.put("package",NativeAppGoal.CTRIP_PACKAGE);j.put("goal_sha256",e.goal.contractSha256);j.put("date",e.goal.departureDate.toString());
        j.put("screen_sha256",e.pngSha256);j.put("left",300);j.put("top",500);j.put("right",400);j.put("bottom",600);return j.toString();}
    public static void main(String[] args)throws Exception{
        out=Paths.get(args[0]);work=Paths.get(args[1]);Files.createDirectory(work);
        BufferedImage image=new BufferedImage(1224,2992,BufferedImage.TYPE_INT_RGB);java.awt.Graphics2D g=image.createGraphics();g.setColor(Color.WHITE);g.fillRect(0,0,1224,2992);g.setColor(Color.BLACK);g.drawString("synthetic 2026/11",90,230);g.drawString("25",330,550);g.dispose();
        ByteArrayOutputStream bytes=new ByteArrayOutputStream();if(!ImageIO.write(image,"png",bytes))throw new IOException("PNG writer");png=bytes.toByteArray();
        one("actual_form_year_calendar_offer_keeps_prior22_target25_and_exact_grammar",()->{Env e=new Env();NativeAppSession.CalendarOffer offer=e.offer();DecisionGrammar gr=offer.grammar();
            check(offer.priorObservedFormDate.toString().equals("2026-11-22"),"prior FORM date is not target");check(offer.source.goal.departureDate.toString().equals("2026-11-25"),"immutable target");
            check(gr.schema.equals(NativeCalendarDateIntent.SCHEMA)&&gr.text.equals(offer.protocol.grammar)&&gr.sha256.equals(offer.protocol.grammarSha256),"exact protocol grammar");
            check(gr.targets.labels.isEmpty()&&gr.scrollDirections.isEmpty()&&gr.submitNodes.isEmpty()&&gr.fixedIntentTargets.isEmpty()&&gr.doneStatuses.isEmpty()&&!gr.successAllowed,"no legacy capabilities");
            check(gr.actions.equals(Collections.singletonList(NativeCalendarDateIntent.ACTION)),"one new intent");check(NativeCalendarDateIntent.parse(raw(e.envelope),e.envelope).date.equals("2026-11-25"),"actual new parser");
            reject(()->ActionDecision.parse(raw(e.envelope)));reject(()->ActionDecision.parse(raw(e.envelope),gr.schema));
            check(Boolean.FALSE.equals(offer.evidence().get("calendar_permit_issued"))&&e.model.calls==0,"no model or effect permit");});
        one("actual_click_deny_stops_before_calendar_offer",()->reject(()->new Env(OWNER+"，禁止点击")));
        one("same_authorization_different_actual_gate_refused",()->{Env e=new Env();NativeAppSession.CalendarOffer offer=e.offer();
            reject(()->DecisionGrammar.createNativeCalendarAuthorized(offer,e.auth.bind(TASK).frame()));check(offer.grammar()!=null,"original actual Gate still valid");});
        one("same_values_new_selection_and_goal_do_not_rebind_original_envelope",()->{Env e=new Env(),other=new Env();
            check(e.goal!=other.goal&&e.goal.contractSha256.equals(other.goal.contractSha256),"equal value different goal objects");
            reject(()->other.session.offerCalendarDate(e.envelope,other.model,other.clock,START+30000));});
        one("copied_frame_cannot_replace_registered_actual_frame",()->{Env e=new Env();NativeAppEvidence.Frame copy=e.frame(calendarNodes(),START+200,e.calendarFrame.observationId);
            NativeCalendarDateEnvelope copied=e.envelope(copy);reject(()->e.session.offerCalendarDate(copied,e.model,e.clock,START+30000));});
        one("fresh_reobservation_does_not_reset_old_offer_slot",()->{Env e=new Env();NativeAppSession.CalendarOffer offer=e.offer();
            e.clock.now=START+310;NativeAppEvidence.Frame fresh=e.frame(calendarNodes(),START+300,id());e.session.observed(fresh);
            reject(()->offer.grammar());reject(()->e.session.offerCalendarDate(e.envelope(fresh),e.model,e.clock,START+30000));});
        one("grammar_factory_mints_once_and_cannot_compact_into_second_object",()->{Env e=new Env();NativeAppSession.CalendarOffer offer=e.offer();DecisionGrammar gr=offer.grammar();
            check(gr==offer.grammar(),"same cached grammar");reject(()->DecisionGrammar.createNativeCalendarAuthorized(offer,e.gate.frame()));reject(()->gr.compactReasonAndWhitespace());});
        one("close_does_not_restore_task_session_offer",()->{Env e=new Env();NativeAppSession.CalendarOffer offer=e.offer();offer.close();
            reject(()->offer.grammar());reject(()->e.offer());check(offer.closed(),"closed original retained");});
        one("offer_journal_failure_consumes_original_slot",()->{Env e=new Env();e.failOfferJournal=true;reject(()->e.offer());e.failOfferJournal=false;reject(()->e.offer());
            check(!e.journalLeaves.contains("native-calendar-date-offer.json"),"no fake durable successful offer");});
        one("changed_private_png_refuses_original_grammar",()->{Env e=new Env();NativeAppSession.CalendarOffer offer=e.offer();Files.write(e.image,new byte[]{1,2,3},StandardOpenOption.TRUNCATE_EXISTING);reject(()->offer.grammar());});
        one("retired_currentframe_callback_refuses_original_offer",()->{Env e=new Env();NativeAppSession.CalendarOffer offer=e.offer();e.live=false;reject(()->offer.grammar());});
        one("observe_only_lfm_default_or_nonimage_runtime_cannot_get_offer",()->{
            for(LocalRuntimeConfig cfg:new LocalRuntimeConfig[]{new LocalRuntimeConfig(ModelProfile.GUI_OWL_4B,"npu",8192,4,true),new LocalRuntimeConfig(ModelProfile.LFM3_VL_2B,"npu",8192,4,true),LocalRuntimeConfig.defaults()}){
                Env e=new Env();e.model.config=cfg;reject(()->e.offer());check(e.model.calls==0,"no hidden fallback request");}
            Env e=new Env();e.model.images=false;reject(()->e.offer());});
        one("same_value_new_runtime_configuration_object_refused",()->{Env e=new Env();NativeAppSession.CalendarOffer offer=e.offer();e.model.config=gui();reject(()->offer.grammar());});
        one("installation_rechecked_before_model_grammar",()->{Env e=new Env();NativeAppSession.CalendarOffer offer=e.offer();int before=e.installationChecks;e.installation=false;
            reject(()->offer.grammar());check(e.installationChecks>before,"actual installation callback invoked");});
        one("model_admission_stale_deadline_and_backward_clock_refused",()->{Env e=new Env();NativeAppSession.CalendarOffer offer=e.offer();e.clock.now=START+2201;reject(()->offer.grammar());
            Env d=new Env();reject(()->d.session.offerCalendarDate(d.envelope,d.model,d.clock,d.clock.now));
            Env back=new Env();NativeAppSession.CalendarOffer own=back.offer();back.clock.now=START+199;reject(()->own.grammar());});
        one("session_and_actual_gate_retirement_close_admission",()->{Env e=new Env();NativeAppSession.CalendarOffer offer=e.offer();e.session.retire();reject(()->offer.grammar());check(offer.closed(),"session close cascades");
            Env q=new Env();NativeAppSession.CalendarOffer other=q.offer();q.gate.retire();reject(()->other.grammar());});
        one("legacy_route_only_accepts_failure_partial_after_calendar_offer",()->{
            for(String status:new String[]{"failure","partial"}){Env e=new Env();e.offer();String run=id();ActionDecision done=action(e.calendarFrame,"done",status,null);
                e.session.beforeModelAction(2,done,run,START+250);e.session.modelActionOutcome(done,run,true,false,false,hash("synthetic-no-effect-terminal"),START+260);check(e.model.calls==0,"no model invoked by consumption");}
            Env e=new Env();e.offer();for(String kind:new String[]{"wait","back"}){ActionDecision a=action(e.calendarFrame,kind,null,null);reject(()->e.session.beforeModelAction(2,a,id(),START+250));}
            ActionDecision success=action(e.calendarFrame,"done","success",null);reject(()->e.session.beforeModelAction(2,success,id(),START+250));});
        one("new_calendar_frame_cannot_borrow_original_inspection_after",()->{Env e=new Env();e.clock.now=START+310;NativeAppEvidence.Frame newer=e.frame(calendarNodes(),START+300,id());e.session.observed(newer);
            reject(()->e.session.offerCalendarDate(e.envelope(newer),e.model,e.clock,START+30000));});
        boolean all=true;for(Map<String,Object> r:cases)all&=Boolean.TRUE.equals(r.get("passed"));
        Map<String,Object> result=new LinkedHashMap<String,Object>();result.put("schema","hepta.calendar-session-offer-host.v1");result.put("all_pass",all);result.put("cases",cases.size());result.put("assertions",assertions);result.put("results",cases);
        result.put("actual_session_goal_gate_domain_grammar_parser",true);result.put("synthetic_android_profile_clock_installed_and_action_receipt_ports",true);
        result.put("actual_vlm_model_receipt_producer_tested",false);result.put("android_input_or_calendar_permit_issued",false);result.put("model_executions",0);result.put("phone_operations",0);
        Files.write(out.resolve("CASES.json"),(new JSONObject(result).toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        System.out.println("calendar Session "+cases.size()+" / "+assertions+" passed="+all);if(!all)throw new AssertionError("necessary calendar Session case failed");
    }
}
