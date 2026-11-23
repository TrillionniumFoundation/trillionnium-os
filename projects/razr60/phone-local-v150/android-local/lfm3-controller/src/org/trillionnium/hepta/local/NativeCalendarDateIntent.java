package org.trillionnium.hepta.local;

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

/** Separate model proposal. No ActionDecision, platform input or successful date
 * receipt can be constructed from this object. A rectangle is an unverified local
 * visual grounding claim, not an observed AX day cell.
 */
final class NativeCalendarDateIntent {
    static final String SCHEMA="hepta.native-calendar-select-date.v1",ACTION="calendar.select_date";
    private static final Set<String> KEYS=Collections.unmodifiableSet(new TreeSet<String>(Arrays.asList(
            "reason","action","observation_id","package","goal_sha256","date","screen_sha256","left","top","right","bottom")));
    final String reason,observationId,packageName,goalSha256,date,pngSha256;
    final Rect cell;
    private NativeCalendarDateIntent(Map<String,Object> f,Rect cell){
        reason=(String)f.get("reason");observationId=(String)f.get("observation_id");packageName=(String)f.get("package");
        goalSha256=(String)f.get("goal_sha256");date=(String)f.get("date");pngSha256=(String)f.get("screen_sha256");this.cell=cell;
    }
    static NativeCalendarDateIntent parse(String raw,NativeCalendarDateEnvelope expected)throws ActionDecision.InvalidActionException{
        Map<String,Object> f=ActionDecision.strictFields(raw);
        need(expected!=null&&f.keySet().equals(KEYS),"exact calendar select-date fields required");
        for(String k:Arrays.asList("reason","action","observation_id","package","goal_sha256","date","screen_sha256"))
            need(f.get(k) instanceof String,"calendar string type differs: "+k);
        for(String k:Arrays.asList("left","top","right","bottom"))need(f.get(k) instanceof Integer,"calendar pixel coordinates must be canonical integers");
        String why=(String)f.get("reason");need(!why.isEmpty()&&why.codePointCount(0,why.length())<=96,"reason must contain 1..96 Unicode code points");
        need(ACTION.equals(f.get("action"))&&expected.facts.observationId.equals(f.get("observation_id"))
                &&NativeAppGoal.CTRIP_PACKAGE.equals(f.get("package"))&&expected.goal.contractSha256.equals(f.get("goal_sha256"))
                &&expected.goal.departureDate.toString().equals(f.get("date"))&&expected.pngSha256.equals(f.get("screen_sha256")),
                "intent is not bound to the original goal and pixel observation");
        Rect cell;
        try{cell=new Rect((Integer)f.get("left"),(Integer)f.get("top"),(Integer)f.get("right"),(Integer)f.get("bottom"));}
        catch(IllegalArgumentException invalid){throw new ActionDecision.InvalidActionException(invalid.getMessage());}
        need(expected.monthRegion.contains(cell),"one cell rectangle must be entirely within the actually observed target-month region");
        return new NativeCalendarDateIntent(f,cell);
    }
    Map<String,Object> evidence(){Map<String,Object> e=new LinkedHashMap<String,Object>();e.put("schema",SCHEMA);e.put("action",ACTION);
        e.put("observation_id",observationId);e.put("package",packageName);e.put("goal_sha256",goalSha256);e.put("date",date);
        e.put("screen_sha256",pngSha256);e.put("cell",cell.evidence());e.put("reason",reason);
        e.put("cell_is_model_grounding_claim",true);e.put("grants_dispatch_authority",false);return NativeAppEvidence.immutableMap(e);}
    static final class Rect {
        final int left,top,right,bottom;
        Rect(int l,int t,int r,int b){if(l<0||t<0||r<=l||b<=t||r>8192||b>8192)
            throw new IllegalArgumentException("one nonempty bounded integer pixel rectangle required");left=l;top=t;right=r;bottom=b;}
        boolean contains(Rect r){return r!=null&&r.left>=left&&r.top>=top&&r.right<=right&&r.bottom<=bottom;}
        boolean same(Rect r){return r!=null&&left==r.left&&top==r.top&&right==r.right&&bottom==r.bottom;}
        Map<String,Object> evidence(){Map<String,Object> m=new LinkedHashMap<String,Object>();m.put("left",left);m.put("top",top);m.put("right",right);m.put("bottom",bottom);return Collections.unmodifiableMap(m);}
    }
    private static void need(boolean ok,String why)throws ActionDecision.InvalidActionException{if(!ok)throw new ActionDecision.InvalidActionException(why);}
}
