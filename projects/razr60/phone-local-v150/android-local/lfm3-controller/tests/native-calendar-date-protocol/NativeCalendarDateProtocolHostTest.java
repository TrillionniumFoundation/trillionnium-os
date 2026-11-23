package org.trillionnium.hepta.local;

import java.awt.Color;
import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import javax.imageio.ImageIO;
import org.json.JSONObject;
import org.trillionnium.hepta.background.ProfileTarget;
import org.trillionnium.hepta.background.WindowOwnership;

/** Pure protocol gate. All AX facts, clocks, Currentness and profile/task data
 * are explicit synthetic host inputs. Real PNG files/private-file code, actual
 * Goal/Profile/Window/Frame/provider/parser classes are executed. No authority
 * Offer, Android screenshot, model, input, broker or phone is simulated as PASS. */
public final class NativeCalendarDateProtocolHostTest {
    static final long START=1000000L;
    static final String OWNER="在携程查询2026年11月25日北京到上海的单程机票，1名成人";
    static final String TASK="55555555555555555555555555555555",GEN="11111111-1111-4111-8111-111111111111",TOKEN="22222222-2222-4222-8222-222222222222";
    static Path work,output;static int assertions;static byte[] PNG,OTHER;
    static final List<Map<String,Object>> cases=new ArrayList<Map<String,Object>>(),vectors=new ArrayList<Map<String,Object>>();
    interface Work {void run()throws Exception;}
    static void check(boolean v,String why){assertions++;if(!v)throw new AssertionError(why);}
    static void reject(Work w)throws Exception{boolean bad=false;try{w.run();}catch(IllegalArgumentException|IllegalStateException|IOException|ActionDecision.InvalidActionException e){bad=true;}check(bad,"required rejection missing");}
    static void one(String n,Work w){Map<String,Object> r=new LinkedHashMap<String,Object>();r.put("name",n);int before=assertions;
        try{w.run();r.put("passed",true);}catch(Throwable t){r.put("passed",false);r.put("error",t.toString());java.io.StringWriter sw=new java.io.StringWriter();t.printStackTrace(new java.io.PrintWriter(sw));r.put("stack",sw.toString());}
        r.put("assertions",assertions-before);cases.add(r);}
    static String hash(String s){return NativeAppEvidence.hash(s);}static String id(){return UUID.randomUUID().toString().replace("-","");}
    static final class Clock implements NativeCalendarDateProtocol.Clock {long value=START+10,step;public long elapsedRealtime(){long now=value;value+=step;return now;}}
    static final class Spec {
        final Clock clock=new Clock();final ProfileTarget profile=NativeProfileIdentityHostTest.ctrip();
        final BackgroundSession.Selection selected=NativeProfileIdentityHostTest.selection(OWNER,profile);
        final TaskAuthorization auth=TaskAuthorization.parse(OWNER).forExecutionSelection(selected);
        final NativeAppGoal goal=selected.taskTarget.nativeGoal;
        long captured=START;int display=15,window=96,rotation=0,width=1224,height=2992;
        String observation=id(),record=hash(id()),tree=hash("synthetic-complete-calendar-tree"),state=hash("synthetic-calendar-state"),owner=goal.ownerSha256;
        String month="2026年11月",nextMonth="2026年12月",ownerBytes=OWNER;boolean duplicateMonth,live=true,complete=true;
        Path image;byte[] png=PNG;String declaredSha;NativeAppEvidence.Frame facts;LocalInference.CurrentFrame current;
        Spec()throws Exception{image=Files.createTempFile(work,"actual-synthetic-png-",".png");writeImage(image,png);}
        void fresh(long at)throws Exception{captured=at;clock.value=at+10;observation=id();record=hash(id());}
        NativeAppEvidence.Frame frame(List<NativeAppEvidence.Node> nodes){
            WindowOwnership proof=new WindowOwnership(profile,GEN,display,window,1234,1200,TOKEN,UUID.randomUUID().toString(),
                    profile.profile.userId,profile.profile.serial,profile.fullUid,captured,captured+8000);
            return new NativeAppEvidence.Frame(TASK,owner,selected.taskTarget.targetSha256,auth.sha256,hash("same-synthetic-selection"),
                    observation,NativeAppGoal.CTRIP_PACKAGE,GEN,tree,state,declaredSha==null?MobiMindContract.sha(png):declaredSha,record,
                    hash("synthetic-completion-"+observation),display,window,rotation,width,height,0,0,width,height,captured,false,complete,nodes,1,true,proof);
        }
        NativeCalendarDateEnvelope envelope()throws Exception{return envelope(new LocalRuntimeConfig(ModelProfile.GUI_OWL_4B,"npu",8192,4,false));}
        NativeCalendarDateEnvelope envelope(LocalRuntimeConfig runtime)throws Exception{
            facts=frame(calendar(this));current=new LocalInference.CurrentFrame(image.toFile(),TASK,owner,observation,GEN,NativeAppGoal.CTRIP_PACKAGE,
                    declaredSha==null?MobiMindContract.sha(png):declaredSha,width,height,display,window,rotation,captured,
                    ownerBytes.getBytes(StandardCharsets.UTF_8),()->{if(!live)throw new IllegalStateException("synthetic ownership retired");});
            return NativeCalendarDateEnvelope.capture(goal,facts,current,profile,runtime,clock);
        }
    }
    static void writeImage(Path p,byte[] png)throws Exception{Files.write(p,png);Files.setPosixFilePermissions(p,PosixFilePermissions.fromString("rw-------"));}
    static byte[] png(boolean changed)throws Exception{BufferedImage image=new BufferedImage(1224,2992,BufferedImage.TYPE_INT_RGB);
        java.awt.Graphics2D g=image.createGraphics();g.setColor(Color.WHITE);g.fillRect(0,0,1224,2992);g.setColor(Color.BLACK);g.drawString("2026/11 synthetic calendar",80,230);g.drawString("25",330,550);
        if(changed){g.setColor(Color.RED);g.fillRect(1000,2500,3,3);}g.dispose();ByteArrayOutputStream out=new ByteArrayOutputStream();check(ImageIO.write(image,"png",out),"real PNG writer");return out.toByteArray();}
    static NativeAppEvidence.Node node(String id,String path,String cls,String parent,String view,String text,int l,int t,int r,int b,boolean scroll){
        return new NativeAppEvidence.Node(id,NativeAppGoal.CTRIP_PACKAGE,cls,view,text,"",path,parent,hash("synthetic-ref-"+path),text,l,t,r,b,
                true,false,false,false,scroll,false,false,false,scroll?Collections.singleton("down"):Collections.<String>emptySet());}
    static List<NativeAppEvidence.Node> calendar(Spec s){List<NativeAppEvidence.Node> n=new ArrayList<NativeAppEvidence.Node>();
        n.add(node("n1","0","android.widget.FrameLayout","","","",0,0,1224,2992,false));
        n.add(node("n2","0/0","android.widget.ListView","android.widget.FrameLayout","ctrip.android.view:id/calendar_list","",50,200,1174,2400,true));
        n.add(node("n3","0/0/0","android.widget.LinearLayout","android.widget.ListView","","",50,200,1174,1800,false));
        n.add(node("n4","0/0/0/0","android.widget.LinearLayout","android.widget.LinearLayout","","",50,200,1174,260,false));
        n.add(node("n5","0/0/0/0/0","android.widget.TextView","android.widget.LinearLayout","ctrip.android.view:id/calendar_month_title_left_tv",s.month,50,200,1174,260,false));
        n.add(node("n6","0/0/1","android.widget.LinearLayout","android.widget.ListView","","",50,1900,1174,2400,false));
        n.add(node("n7","0/0/1/0","android.widget.LinearLayout","android.widget.LinearLayout","","",50,1900,1174,1960,false));
        n.add(node("n8","0/0/1/0/0","android.widget.TextView","android.widget.LinearLayout","ctrip.android.view:id/calendar_month_title_left_tv",s.duplicateMonth?s.month:s.nextMonth,50,1900,1174,1960,false));return n;}
    static String json(Map<String,Object> fields){StringBuilder s=new StringBuilder("{");boolean first=true;for(Map.Entry<String,Object> e:fields.entrySet()){
        if(!first)s.append(',');first=false;s.append(JSONObject.quote(e.getKey())).append(':');Object v=e.getValue();s.append(v instanceof String?JSONObject.quote((String)v):String.valueOf(v));}return s.append('}').toString();}
    static Map<String,Object> fields(NativeCalendarDateEnvelope e){Map<String,Object> f=new LinkedHashMap<String,Object>();f.put("reason","选择目标日期格");f.put("action",NativeCalendarDateIntent.ACTION);
        f.put("observation_id",e.facts.observationId);f.put("package",NativeAppGoal.CTRIP_PACKAGE);f.put("goal_sha256",e.goal.contractSha256);f.put("date",e.goal.departureDate.toString());
        f.put("screen_sha256",e.pngSha256);f.put("left",300);f.put("top",500);f.put("right",400);f.put("bottom",600);return f;}
    static String repeat(String value,int count){StringBuilder s=new StringBuilder();for(int i=0;i<count;i++)s.append(value);return s.toString();}
    static NativeCalendarDateProtocol protocol(NativeCalendarDateEnvelope e)throws Exception{NativeCalendarDateProtocol p=new NativeCalendarDateProtocol(e);p.propose(json(fields(e)),id(),START+1000,START+9000,START+30000);return p;}
    static Spec replacement(Spec a,long at)throws Exception{Spec b=new Spec();b.fresh(at);return b;}
    static NativeCalendarDateEnvelope replacementEnvelope(Spec a,Spec b)throws Exception{
        // The real goal object is immutable and belongs to a single task. A new
        // frame does not recreate it. All other synthetic facts use the same selection.
        b.facts=b.frame(calendar(b));b.current=new LocalInference.CurrentFrame(b.image.toFile(),TASK,b.owner,b.observation,GEN,NativeAppGoal.CTRIP_PACKAGE,
                b.declaredSha==null?MobiMindContract.sha(b.png):b.declaredSha,b.width,b.height,b.display,b.window,b.rotation,b.captured,
                b.ownerBytes.getBytes(StandardCharsets.UTF_8),()->{if(!b.live)throw new IllegalStateException("synthetic ownership retired");});
        return NativeCalendarDateEnvelope.capture(a.goal,b.facts,b.current,b.profile,new LocalRuntimeConfig(ModelProfile.GUI_OWL_4B,"npu",8192,4,false),b.clock);
    }
    static NativeAppEvidence.Frame form(Spec base,long at,String date)throws Exception{Spec s=replacement(base,at);
        NativeActionSnapshotCheckHostTest.Fixture f=NativeActionSnapshotCheckHostTest.form(NativeActionSnapshotCheck.YEAR);
        f.nodes.get("0/0/2/5").put("text",date);f.nodes.get("0/0/2/5").put("label",date);
        List<NativeAppEvidence.Node> nodes=new ArrayList<NativeAppEvidence.Node>();int index=1;
        for(Map<String,Object> v:f.nodes.values()){
            List<?> b=(List<?>)v.get("bounds");nodes.add(new NativeAppEvidence.Node("n"+(index++),NativeAppGoal.CTRIP_PACKAGE,(String)v.get("class"),(String)v.get("view_id"),
                    (String)v.get("text"),(String)v.get("description"),(String)v.get("path"),(String)v.get("parent_class"),(String)v.get("ref_signature_sha256"),
                    (String)v.get("label"),(Integer)b.get(0),(Integer)b.get(1),(Integer)b.get(2),(Integer)b.get(3),
                    (Boolean)v.get("enabled"),(Boolean)v.get("password"),(Boolean)v.get("clickable"),(Boolean)v.get("editable"),(Boolean)v.get("scrollable"),
                    (Boolean)v.get("selected"),(Boolean)v.get("checkable"),(Boolean)v.get("checked"),Collections.<String>emptySet()));}
        return s.frame(nodes);
    }
    static void vector(String name,String raw,boolean accept){Map<String,Object> v=new LinkedHashMap<String,Object>();v.put("name",name);v.put("raw",raw);v.put("expected",accept);vectors.add(v);}
    public static void main(String[] args)throws Exception{
        output=Paths.get(args[0]);work=Paths.get(args[1]);Files.createDirectory(work);PNG=png(false);OTHER=png(true);
        one("actual_png_complete_calendar_and_profile_bound_without_authority",()->{Spec s=new Spec();NativeCalendarDateEnvelope e=s.envelope();
            check(e.monthRegion.top==260&&e.monthRegion.bottom==1900,"actual month boundaries");check(e.facts.profileWindow.fullUid==1010367,"actual complete full UID");
            check(Boolean.FALSE.equals(e.evidence().get("grants_dispatch_authority")),"envelope cannot grant action");check(MobiMindContract.sha(Files.readAllBytes(s.image)).equals(e.pngSha256),"real file hash");});
        one("strict_intent_and_independent_grammar_are_not_legacy_actions",()->{Spec s=new Spec();NativeCalendarDateEnvelope e=s.envelope();String raw=json(fields(e));
            NativeCalendarDateIntent v=NativeCalendarDateIntent.parse(raw,e);check(v.date.equals("2026-11-25")&&v.cell.left==300,"fixed date and rectangle");reject(()->ActionDecision.parse(raw));
            NativeCalendarDateProtocol p=new NativeCalendarDateProtocol(e);Files.write(output.resolve("calendar.gbnf"),p.grammar.getBytes(StandardCharsets.UTF_8));
            Files.write(output.resolve("envelope.json"),new JSONObject(e.evidence()).toString(2).getBytes(StandardCharsets.UTF_8));vector("one_valid_fixed_intent",raw,true);
            Map<String,Object> f=fields(e);f.put("action","tap");vector("arbitrary_tap",json(f),false);f=fields(e);f.put("date","2026-11-24");vector("different_fixed_date",json(f),false);
            f=fields(e);f.put("reason",repeat("😀",96));vector("96_astral_reason",json(f),true);f=fields(e);f.put("reason",repeat("😀",97));vector("97_astral_reason",json(f),false);
            f=fields(e);f.put("reason","引号\" 反斜线\\ 换行\n制表\t");vector("json_escapes",json(f),true);f=fields(e);f.put("x",350);vector("extra_coordinate",json(f),false);
            vector("duplicate_reason",raw.substring(0,raw.length()-1)+",\"reason\":\"x\"}",false);vector("float_coordinate",raw.replace("\"left\":300","\"left\":300.0"),false);
            vector("negative_coordinate",raw.replace("\"left\":300","\"left\":-1"),false);vector("overflow_coordinate",raw.replace("\"left\":300","\"left\":2147483648"),false);
            f=fields(e);f.put("reason","");vector("empty_reason",json(f),false);
            vector("unicode_escape_parser_accepts_but_generation_subset_refuses",raw.replace("选择目标日期格","\\u9009\\u62e9"),false);});
        one("duplicate_extra_missing_and_nested_fields_refused",()->{Spec s=new Spec();NativeCalendarDateEnvelope e=s.envelope();String raw=json(fields(e));
            reject(()->NativeCalendarDateIntent.parse(raw.substring(0,raw.length()-1)+",\"reason\":\"again\"}",e));
            reject(()->NativeCalendarDateIntent.parse(raw.substring(0,raw.length()-1)+",\"r\\u0065ason\":\"again\"}",e));
            for(String key:new String[]{"x","y","status","schema","login"}){Map<String,Object> f=fields(e);f.put(key,"unexpected");reject(()->NativeCalendarDateIntent.parse(json(f),e));}
            for(String key:new String[]{"date","goal_sha256","left"}){Map<String,Object> f=fields(e);f.remove(key);reject(()->NativeCalendarDateIntent.parse(json(f),e));}
            reject(()->NativeCalendarDateIntent.parse(raw.replace("\"left\":300","\"left\":{\"x\":300}"),e));});
        one("reason_unicode_and_json_escape_boundaries",()->{Spec s=new Spec();NativeCalendarDateEnvelope e=s.envelope();
            for(String reason:new String[]{repeat("😀",96),repeat("日",96),"引号\"反斜线\\换行\n"}){Map<String,Object> f=fields(e);f.put("reason",reason);check(NativeCalendarDateIntent.parse(json(f),e).reason.equals(reason),"actual Unicode/escape decoding");}
            for(String reason:new String[]{"",repeat("😀",97),repeat("x",97)}){Map<String,Object> f=fields(e);f.put("reason",reason);reject(()->NativeCalendarDateIntent.parse(json(f),e));}
            String raw=json(fields(e));check(NativeCalendarDateIntent.parse(raw.replace("选择目标日期格","\\u9009\\u62e9"),e).reason.equals("选择"),"JSON Unicode escape semantic decoding");
            check(NativeCalendarDateIntent.parse(raw.replace("选择目标日期格","\\ud83d\\ude00"),e).reason.equals("😀"),"paired JSON surrogate escape decoding");
            reject(()->NativeCalendarDateIntent.parse(raw.replace("选择目标日期格","\\ud800"),e));});
        one("canonical_integer_overflow_nan_float_exponent_and_negative_refused",()->{Spec s=new Spec();NativeCalendarDateEnvelope e=s.envelope();String raw=json(fields(e));
            for(String token:new String[]{"NaN","Infinity","300.0","3e2","2147483648","-2147483649","-1","-0","0300","\"300\"","null","true"})
                reject(()->NativeCalendarDateIntent.parse(raw.replace("\"left\":300","\"left\":"+token),e));});
        one("rectangle_positive_area_screen_and_month_boundaries",()->{Spec s=new Spec();NativeCalendarDateEnvelope e=s.envelope();
            for(int[] b:new int[][]{{400,500,300,600},{300,600,400,600},{0,500,400,600},{300,200,400,600},{300,500,1300,600},{300,500,400,1901},{-1,500,400,600}}){
                Map<String,Object> f=fields(e);int i=0;for(String k:new String[]{"left","top","right","bottom"})f.put(k,b[i++]);reject(()->NativeCalendarDateIntent.parse(json(f),e));}});
        one("date_goal_observation_package_and_png_are_fixed",()->{Spec s=new Spec();NativeCalendarDateEnvelope e=s.envelope();
            for(String k:new String[]{"action","observation_id","package","goal_sha256","date","screen_sha256"}){Map<String,Object> f=fields(e);f.put(k,"different");reject(()->NativeCalendarDateIntent.parse(json(f),e));}});
        one("only_explicit_gui_owl_tools_and_never_observe_only",()->{for(LocalRuntimeConfig cfg:new LocalRuntimeConfig[]{new LocalRuntimeConfig(ModelProfile.GUI_OWL_4B,"npu",8192,4,true),
                new LocalRuntimeConfig(ModelProfile.LFM3_VL_2B,"npu",8192,4,true),LocalRuntimeConfig.defaults()}){Spec s=new Spec();reject(()->s.envelope(cfg));}});
        one("frame_geometry_identity_and_currentness_mismatch_refused",()->{Spec size=new Spec();size.width=1223;reject(()->size.envelope());
            Spec other=new Spec();other.owner=hash("other-owner");reject(()->other.envelope());Spec retired=new Spec();retired.live=false;reject(()->retired.envelope());
            Spec incomplete=new Spec();incomplete.complete=false;reject(()->incomplete.envelope());
            Spec wrongBytes=new Spec();wrongBytes.ownerBytes="different synthetic instruction";reject(()->wrongBytes.envelope());});
        one("requested_month_missing_ambiguous_or_wrong_year_refused",()->{for(String month:new String[]{"2025年11月","2026年10月","11月"}){Spec s=new Spec();s.month=month;reject(()->s.envelope());}
            Spec duplicate=new Spec();duplicate.duplicateMonth=true;reject(()->duplicate.envelope());});
        one("actual_private_png_hash_mode_and_symlink_refused",()->{Spec s=new Spec();s.declaredSha=hash("not-the-png");reject(()->s.envelope());
            Spec wrongMode=new Spec();Files.setPosixFilePermissions(wrongMode.image,PosixFilePermissions.fromString("rw-r--r--"));reject(()->wrongMode.envelope());
            Spec link=new Spec();Path target=link.image;link.image=work.resolve("symlink-"+id());Files.createSymbolicLink(link.image,target);reject(()->link.envelope());});
        one("capture_two_second_bound_rechecked_after_io",()->{Spec old=new Spec();old.clock.value=START+2001;reject(()->old.envelope());
            Spec delayed=new Spec();delayed.clock.step=3000;reject(()->delayed.envelope());});
        one("one_model_proposal_and_one_fresh_capture_consumption_only",()->{Spec a=new Spec();NativeCalendarDateEnvelope first=a.envelope();NativeCalendarDateProtocol p=protocol(first);
            reject(()->p.propose(json(fields(first)),id(),START+1000,START+9000,START+30000));Spec b=replacement(a,START+1500);NativeCalendarDateEnvelope fresh=replacementEnvelope(a,b);
            NativeCalendarDateProtocol.Consumption c=p.consumeFresh(fresh,b.clock);check(p.consumed(),"consumed once");check(Boolean.FALSE.equals(c.evidence().get("grants_broker_or_service_authority")),"consumption is not a permit");
            reject(()->p.consumeFresh(fresh,b.clock));});
        one("old_pixels_path_clock_and_observation_cannot_be_relabelled",()->{for(int variant=0;variant<4;variant++){Spec a=new Spec();NativeCalendarDateEnvelope first=a.envelope();NativeCalendarDateProtocol p=protocol(first);
                Spec b=replacement(a,variant==2?START+900:START+1500);if(variant==0)b.image=a.image;if(variant==1)b.observation=a.observation;if(variant==3)b.record=a.record;
                NativeCalendarDateEnvelope fresh=replacementEnvelope(a,b);reject(()->p.consumeFresh(fresh,b.clock));check(p.consumed()&&p.closed(),"rejected fresh check cannot replay");}});
        one("changed_pixels_complete_tree_rotation_or_window_consumes_and_refuses",()->{for(int variant=0;variant<4;variant++){Spec a=new Spec();NativeCalendarDateEnvelope first=a.envelope();NativeCalendarDateProtocol p=protocol(first);
                Spec b=replacement(a,START+1500);if(variant==0){b.png=OTHER;writeImage(b.image,b.png);}if(variant==1)b.tree=hash("changed-complete-tree");if(variant==2)b.rotation=1;if(variant==3)b.window=97;
                NativeCalendarDateEnvelope fresh=replacementEnvelope(a,b);reject(()->p.consumeFresh(fresh,b.clock));check(p.consumed()&&p.closed(),"refusal stays terminal");}});
        one("deadline_cancellation_and_malformed_output_do_not_reopen_slot",()->{Spec a=new Spec();NativeCalendarDateEnvelope first=a.envelope();NativeCalendarDateProtocol p=protocol(first);Spec b=replacement(a,START+1500);
            NativeCalendarDateEnvelope fresh=replacementEnvelope(a,b);b.clock.value=START+9000;reject(()->p.consumeFresh(fresh,b.clock));check(p.closed()&&p.consumed(),"deadline consumed");
            NativeCalendarDateProtocol closed=new NativeCalendarDateProtocol(first);closed.close();reject(()->closed.propose(json(fields(first)),id(),START+1000,START+9000,START+30000));
            NativeCalendarDateProtocol bad=new NativeCalendarDateProtocol(first);reject(()->bad.propose("{}",id(),START+1000,START+9000,START+30000));check(bad.closed(),"bad model remains consumed");});
        one("consumption_uses_same_final_checked_clock_sample",()->{Spec a=new Spec();NativeCalendarDateEnvelope first=a.envelope();NativeCalendarDateProtocol p=protocol(first);Spec b=replacement(a,START+1500);
            NativeCalendarDateEnvelope fresh=replacementEnvelope(a,b);final int[] calls={0};
            NativeCalendarDateProtocol.Clock jump=()->{calls[0]++;return calls[0]>=5?START+9000:START+1510;};
            NativeCalendarDateProtocol.Consumption c=p.consumeFresh(fresh,jump);check(calls[0]==4&&c.consumedElapsed==START+1510,"same final validated time recorded without a fifth read");
            NativeCalendarDateProtocol p2=protocol(first);final int[] later={0};NativeCalendarDateProtocol.Clock expires=()->{later[0]++;return later[0]>=4?START+9000:START+1510;};
            reject(()->p2.consumeFresh(fresh,expires));check(p2.closed()&&p2.consumed(),"final checked expiration consumes and refuses");});
        one("any_subsequent_month_header_cuts_the_geometry",()->{Spec s=new Spec();s.nextMonth="2026年10月";NativeCalendarDateEnvelope e=s.envelope();
            check(e.monthRegion.bottom==1900,"unexpected older month below target still cuts region");Map<String,Object> f=fields(e);f.put("bottom",1950);reject(()->NativeCalendarDateIntent.parse(json(f),e));});
        one("source_file_changed_after_model_cannot_consume",()->{Spec a=new Spec();NativeCalendarDateEnvelope first=a.envelope();NativeCalendarDateProtocol p=protocol(first);Spec b=replacement(a,START+1500);
            NativeCalendarDateEnvelope fresh=replacementEnvelope(a,b);writeImage(a.image,OTHER);reject(()->p.consumeFresh(fresh,b.clock));check(p.closed()&&p.consumed(),"source change terminal");});
        one("fresh_form_match_is_not_independent_year_effect_or_business_success",()->{Spec a=new Spec();NativeCalendarDateEnvelope first=a.envelope();NativeCalendarDateProtocol p=protocol(first);Spec b=replacement(a,START+1500);
            NativeCalendarDateProtocol.Consumption c=p.consumeFresh(replacementEnvelope(a,b),b.clock);
            Map<String,Object> matched=p.assessForm(c,form(a,START+2500,"11月25日周三"),START+2510);check(Boolean.TRUE.equals(matched.get("target_month_day_and_route_passengers_match")),"actual full FORM month/day/route match");
            for(String flag:new String[]{"year_observed_in_form","actual_single_effect_receipt_attached","date_selection_verified","query_executed","business_verified"})check(Boolean.FALSE.equals(matched.get(flag)),"missing actual effect must not claim "+flag);
            check(Boolean.FALSE.equals(p.assessForm(c,form(a,START+2600,"11月22日周日"),START+2610).get("target_month_day_and_route_passengers_match")),"wrong date cannot confirm");
            reject(()->p.assessForm(c,form(a,START+1400,"11月25日周三"),START+1410));});
        Map<String,Object> report=new LinkedHashMap<String,Object>();boolean pass=true;for(Map<String,Object> r:cases)pass&=Boolean.TRUE.equals(r.get("passed"));
        report.put("schema","hepta.native-calendar-date-host.v1");report.put("all_pass",pass);report.put("cases",cases.size());report.put("assertions",assertions);report.put("checks",cases);
        report.put("phone_actions",0);report.put("model_runs",0);report.put("actual_dispatch_tested",false);report.put("actual_session_offer_tested",false);report.put("date_or_business_verified",false);
        Files.write(output.resolve("CASES.json"),new JSONObject(report).toString(2).getBytes(StandardCharsets.UTF_8));
        Map<String,Object> v=new LinkedHashMap<String,Object>();v.put("vectors",vectors);Files.write(output.resolve("GRAMMAR-VECTORS.json"),new JSONObject(v).toString(2).getBytes(StandardCharsets.UTF_8));
        System.out.println(new JSONObject(report).toString());if(!pass)System.exit(1);
    }
}
