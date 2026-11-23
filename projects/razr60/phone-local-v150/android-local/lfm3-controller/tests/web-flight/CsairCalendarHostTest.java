package org.trillionnium.hepta.local;

import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;

/** Actual header-only and stable DOM originals; all mutations are negative host fixtures. */
public final class CsairCalendarHostTest {
    private static int assertions,cases;
    private static String pendingRaw,stableRaw;
    private interface Checked { void run()throws Exception; }
    private static void check(boolean ok,String why){assertions++;if(!ok)throw new AssertionError(why);}
    private static void reject(Checked action,String why)throws Exception{
        cases++;boolean rejected=false;try{action.run();}catch(Exception expected){rejected=true;}
        check(rejected,why);
    }
    private static JSONObject original(String raw)throws Exception{return new JSONObject(raw);}
    private static JSONObject stable()throws Exception{return original(stableRaw);}
    private static JSONObject node(JSONObject dom,String path)throws Exception{
        JSONArray nodes=dom.getJSONArray("nodes");JSONObject out=null;
        for(int i=0;i<nodes.length();i++){JSONObject n=nodes.getJSONObject(i);if(path.equals(n.getString("path"))){
            if(out!=null)throw new AssertionError("fixture duplicate path");out=n;}}
        if(out==null)throw new AssertionError("fixture missing path "+path);return out;
    }
    private static JSONObject dom(String path,String expectedSha)throws Exception{
        byte[] raw=Files.readAllBytes(Paths.get(path));check(sha(raw).equals(expectedSha),"exact original diagnostic");
        JSONObject record=new JSONObject(new String(raw,StandardCharsets.UTF_8));
        JSONObject capture=record.getJSONObject("capture");String encoded=capture.getString("dom_raw_utf8");
        check(sha(encoded.getBytes(StandardCharsets.UTF_8)).equals(capture.getString("dom_sha256")),"exact original inner DOM");
        return new JSONObject(encoded);
    }
    private static String sha(byte[] raw)throws Exception{
        StringBuilder out=new StringBuilder();for(byte b:MessageDigest.getInstance("SHA-256").digest(raw))
            out.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return out.toString();
    }
    private static final String MONTH0="0/1/0/0/0/1/2/0/0";
    private static final String MONTH1="0/1/0/0/0/1/2/0/1";
    private static final String TARGET=MONTH0+"/1/16";
    public static void main(String[] args)throws Exception{
        check(args.length==2,"two exact existing diagnostic fixture paths");
        JSONObject pending=dom(args[0],"386f86ef76923ce994574893bc05eec906f3ef839f32d8a77a68092e0115d986");
        JSONObject loaded=dom(args[1],"f61fd86cb24b212c3434bb5eda1a4e29b65c06c22d3fc4238366f31a324dd7fa");
        check(pending.getJSONArray("nodes").length()==81&&loaded.getJSONArray("nodes").length()==987,"actual fixture node counts");
        pendingRaw=pending.toString();stableRaw=loaded.toString();

        cases++;CsairCalendar first=CsairCalendar.read(pending);
        check(first!=null&&first.headerOnly&&first.months.isEmpty()&&first.dates.isEmpty(),"actual header-only recognized");
        check(!first.forDate("2026-11-17").ready,"header-only cannot supply requested date");
        check(!first.forDate("2026-11-13").ready,"URL depDate is not observed-date proof");

        cases++;CsairCalendar full=CsairCalendar.read(loaded);
        check(full!=null&&!full.headerOnly&&full.months.size()==2,"actual two visible explicit months");
        check(full.dates.size()==41,"actual numeric labels only; no today inference");
        CsairCalendar.Selection date=full.forDate("2026-11-17");
        check(date.ready&&date.target!=null,"actual literal target metadata");
        check(date.target.year==2026&&date.target.month==11&&date.target.day==17,"literal year month day");
        check(date.target.monthHeaderText.equals("2026年11月")&&date.target.monthHeaderPath.equals(MONTH0+"/0"),"actual month heading");
        check(date.target.dayPath.equals(TARGET)&&date.target.dayListPath.equals(MONTH0+"/1"),"actual direct grid relationship");
        check(date.target.domId.isEmpty()&&date.target.dayText.equals("17"),"empty ID is preserved");
        check(date.target.zeroHeightDayList&&date.target.originalAncestors.size()==11,"actual overflow list retained, not called visible");
        check(!date.target.domDisabled&&date.target.domVisibleInViewport,"original DOM booleans");
        check(Boolean.FALSE.equals(date.target.evidence().get("grants_tool_authority")),"no action authority");
        check(Boolean.FALSE.equals(date.target.evidence().get("native_visibility_verified")),"no native visibility claim");
        check(Boolean.FALSE.equals(date.target.evidence().get("css_to_screen_mapping_verified")),"no coordinate mapping");
        check(Boolean.FALSE.equals(date.evidence().get("selected_date_verified")),"not proof of selection");

        cases++;check(!full.forDate("2026-12-17").ready,"next-month offscreen same label is absent");
        check(!full.forDate("2026-11-12").ready,"today is not expanded from host date or cell index");
        check(!full.forDate("2027-11-17").ready,"goal year never fills source year");
        check(!full.forDate("2028-02-29").ready,"valid leap date still needs observed metadata");
        reject(new Checked(){public void run()throws Exception{full.forDate("2026-02-29");}},"invalid nonleap requested date");
        reject(new Checked(){public void run()throws Exception{full.forDate("2026-11-31");}},"invalid requested month day");
        reject(new Checked(){public void run()throws Exception{full.forDate("2026-1-17");}},"canonical request required");

        cases++;JSONObject noDay=stable();node(noDay,TARGET).put("visible_in_viewport",false).put("text","");
        check(!CsairCalendar.read(noDay).forDate("2026-11-17").ready,"missing target stays not ready");
        cases++;JSONObject hiddenMonth=stable();node(hiddenMonth,MONTH0).put("visible_in_viewport",false);
        check(!CsairCalendar.read(hiddenMonth).forDate("2026-11-17").ready,"hidden month ancestry not inferred");
        cases++;JSONObject hiddenHeader=stable();node(hiddenHeader,MONTH0+"/0").put("visible_in_viewport",false);
        check(!CsairCalendar.read(hiddenHeader).forDate("2026-11-17").ready,"hidden heading does not bind year");
        cases++;JSONObject zeroDay=stable();node(zeroDay,TARGET).put("rect_css_pixels",new JSONArray("[349,860,525,860]"));
        check(!CsairCalendar.read(zeroDay).forDate("2026-11-17").ready,"zero-area day not promoted");
        cases++;JSONObject disabled=stable();node(disabled,TARGET).put("disabled",true);
        CsairCalendar.Selection disabledDate=CsairCalendar.read(disabled).forDate("2026-11-17");
        check(!disabledDate.ready&&disabledDate.target.domDisabled,"disabled original target retained but not ready");
        cases++;JSONObject ariaDisabled=stable();node(ariaDisabled,MONTH0+"/1").put("aria_disabled","true");
        check(!CsairCalendar.read(ariaDisabled).forDate("2026-11-17").ready,"disabled container retained");
        cases++;JSONObject otherYear=stable();node(otherYear,MONTH0+"/0").put("text","2027年11月");
        check(!CsairCalendar.read(otherYear).forDate("2026-11-17").ready,"heading year controls date metadata");

        reject(new Checked(){public void run()throws Exception{JSONObject d=stable();node(d,MONTH0+"/0").put("text","11月");CsairCalendar.read(d);}},"missing literal year refused");
        reject(new Checked(){public void run()throws Exception{JSONObject d=stable();node(d,MONTH1+"/0").put("text","2026年11月");CsairCalendar.read(d);}},"duplicate year month refused");
        reject(new Checked(){public void run()throws Exception{JSONObject d=stable();node(d,MONTH0+"/1/15").put("text","17");CsairCalendar.read(d);}},"duplicate exact date refused");
        reject(new Checked(){public void run()throws Exception{JSONObject d=stable();node(d,TARGET).put("text","31");CsairCalendar.read(d);}},"invalid observed month day refused");
        reject(new Checked(){public void run()throws Exception{JSONObject d=stable();node(d,MONTH0+"/1").put("tag","div");CsairCalendar.read(d);}},"zero-height exception only actual ul");
        reject(new Checked(){public void run()throws Exception{JSONObject d=stable();node(d,MONTH0+"/1").put("rect_css_pixels",new JSONArray("[0,447,1224,448]"));CsairCalendar.read(d);}},"nonzero hidden list is not exception");
        reject(new Checked(){public void run()throws Exception{JSONObject d=stable();d.put("truncated",true);CsairCalendar.read(d);}},"truncated frame refused");
        reject(new Checked(){public void run()throws Exception{JSONObject d=stable();d.put("truncation_reasons",new JSONArray("[\"budget\"]"));CsairCalendar.read(d);}},"reported truncation reason refused");
        reject(new Checked(){public void run()throws Exception{JSONObject d=stable();d.put("visited",986);CsairCalendar.read(d);}},"visited/node mismatch refused");
        reject(new Checked(){public void run()throws Exception{JSONObject d=stable();node(d,TARGET).put("visible_in_viewport",1);CsairCalendar.read(d);}},"boolean numeric alias refused");
        reject(new Checked(){public void run()throws Exception{JSONObject d=stable();node(d,TARGET).put("parent_path",MONTH1+"/1");CsairCalendar.read(d);}},"false parent refused");
        reject(new Checked(){public void run()throws Exception{JSONObject d=stable();d.getJSONArray("nodes").put(new JSONObject(node(d,TARGET).toString()));d.put("visited",988);CsairCalendar.read(d);}},"duplicate paths refused");
        reject(new Checked(){public void run()throws Exception{JSONObject d=stable();d.put("origin","https://evil.example");CsairCalendar.read(d);}},"foreign origin refused");
        reject(new Checked(){public void run()throws Exception{JSONObject d=stable();d.put("href","https://m.csair.com.evil.example/booking_new/#/newCalendar");CsairCalendar.read(d);}},"foreign host refused");
        reject(new Checked(){public void run()throws Exception{JSONObject d=stable();d.put("ready_state","loading");CsairCalendar.read(d);}},"noncomplete document refused");
        reject(new Checked(){public void run()throws Exception{JSONObject d=stable();d.put("schema","unknown");CsairCalendar.read(d);}},"unknown schema refused");
        cases++;JSONObject unrelated=stable();unrelated.put("href","https://m.csair.com/booking_new/#/newCalendarExtra");
        check(CsairCalendar.read(unrelated)==null,"unreviewed calendar-like route is unsupported");
        cases++;JSONObject v3=stable();v3.put("schema","hepta.fixed-top-document-dom.v3");
        for(int i=0;i<v3.getJSONArray("nodes").length();i++)v3.getJSONArray("nodes").getJSONObject(i).put("href",JSONObject.NULL);
        check(CsairCalendar.read(v3).forDate("2026-11-17").ready,"v3 extra anchor metadata cannot provide date authority");
        System.out.println("{\"schema\":\"hepta.csair-calendar-host-test.v1\",\"cases\":"+cases
                +",\"assertions\":"+assertions+",\"all_pass\":true,\"phone_actions\":0"
                +",\"native_ax_action_tested\":false,\"query_ready_verified\":false}");
    }
}
