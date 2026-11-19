package org.trillionnium.hepta.background;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.json.JSONArray;
import org.json.JSONObject;

/** Complete personal Notes absence census; every remaining history record is preserved.
 * No task mutation, exclusion of a remembered ID, or profile-10 policy change. */
public final class PublicPersonalNotesHistory {
    private PublicPersonalNotesHistory(){}
    private static final String INTERNAL="  Recent tasks:\n",VISIBLE="  Visible recent tasks (most recent first):\n";
    private static final Pattern HEAD=Pattern.compile("(?m)^  \\* Recent #([0-9]+): (Task\\{([0-9a-f]+) #([0-9]+) [^{}\\r\\n]+\\})$");
    private static final Pattern VHEAD=Pattern.compile("(?m)^  \\* RecentTaskInfo #([0-9]+):[ \\t]*$");
    private static final Pattern AGE=Pattern.compile("(?m)^    lastActiveTime=(0|[1-9][0-9]*) \\(inactive for (0|[1-9][0-9]*)s\\)$");
    private static final Set<Integer> NONE=Collections.emptySet();
    private static void need(boolean ok,String code){if(!ok)throw new IllegalArgumentException(code);}
    private static long decimal(String value){try{need(value!=null&&value.matches("0|[1-9][0-9]*"),"PUBLIC_HISTORY_INTEGER");return Long.parseLong(value);}
        catch(NumberFormatException bad){throw new IllegalArgumentException("PUBLIC_HISTORY_INTEGER_RANGE",bad);}}
    private static Matcher one(Pattern pattern,String text,String code){Matcher m=pattern.matcher(text);need(m.find(),code);Matcher result=pattern.matcher(text);need(result.find()&&!m.find(),code);return result;}
    private static Matcher one(String regex,String text,String code){return one(Pattern.compile(regex,Pattern.MULTILINE),text,code);}
    private static List<Matcher> matches(Pattern pattern,String text){List<Matcher> out=new ArrayList<Matcher>();Matcher scan=pattern.matcher(text);
        while(scan.find()){Matcher saved=pattern.matcher(text);need(saved.find(scan.start()),"PUBLIC_HISTORY_PATTERN");out.add(saved);}return out;}
    private static boolean component(String value){return value!=null&&value.matches("[A-Za-z][A-Za-z0-9_.]*/[A-Za-z_.$][A-Za-z0-9_.$]*");}
    private static void append(StringBuilder out,String value){out.append(value.length()).append(':').append(value).append('\n');}

    private static final class Row {
        final PublicOwnGroupPhysicalFence.RecentRecord fact;final String body,stable,activities,affinityLine,rootAffinityLine;
        final long lastActive,age;boolean visible,hasTask;
        Row(PublicOwnGroupPhysicalFence.RecentRecord f,String body){
            fact=f;this.body=body;activities=one("^    Activities=(\\[[^\\r\\n]*\\])$",body,"PUBLIC_HISTORY_ACTIVITIES").group(1);
            Matcher at=one(AGE,body,"PUBLIC_HISTORY_LAST_ACTIVE");lastActive=decimal(at.group(1));age=decimal(at.group(2));
            stable=body.substring(0,at.start())+"    lastActiveTime="+at.group(1)+" (inactive for 0s)"+body.substring(at.end());
            affinityLine=optional("^    affinity=([^\\r\\n]*)$",body);rootAffinityLine=optional("^    rootAffinity=([^\\r\\n]*)$",body);
            need(!Pattern.compile("(?m)^\\s*(?:affinity|rootAffinity)=").matcher(body).find()
                    ||(!affinityLine.isEmpty()||!rootAffinityLine.isEmpty()),"PUBLIC_HISTORY_AFFINITY_AMBIGUOUS");
        }
        Map<String,Object> evidence(){Map<String,Object> v=new LinkedHashMap<String,Object>();
            v.put("task_id",fact.task);v.put("task_token",fact.token);v.put("user_id",fact.user);v.put("full_uid",fact.uid);
            v.put("root_task_id",fact.root);v.put("last_display_id",fact.display);v.put("label",fact.label);
            v.put("label_affinity",fact.affinity);v.put("affinity",affinityLine);v.put("root_affinity",rootAffinityLine);
            v.put("base_component",fact.base);v.put("activity_component",fact.activity);v.put("intent_flags",fact.flags);
            v.put("activities",activities);v.put("last_active_time",lastActive);v.put("inactive_seconds",age);
            v.put("visible_recent",visible);v.put("visible_has_task",visible?Boolean.valueOf(hasTask):JSONObject.NULL);
            v.put("stable_body_sha256",ProfileIdentity.sha(stable));return Collections.unmodifiableMap(v);}
    }
    private static String optional(String regex,String text){Matcher m=Pattern.compile(regex,Pattern.MULTILINE).matcher(text);
        if(!m.find())return "";String value=m.group(1);need(!m.find(),"PUBLIC_HISTORY_DUPLICATE_AFFINITY");return value;}
    private static final class VisibleRow {
        final int id;final String stable;
        VisibleRow(int id,String stable){this.id=id;this.stable=stable;}
    }
    public static final class Snapshot {
        private final String raw,preamble;private final boolean hiddenField;
        private final PublicPersonalNotesAbsenceRecovery.Request request;
        private final PublicOwnGroupPhysicalFence.RecentCensus census;
        private final Map<Integer,Row> rows;private final List<VisibleRow> visible;
        private final Map<Integer,String> tokens;
        private Snapshot(String raw,PublicPersonalNotesAbsenceRecovery.Request request)throws Exception{
            need(request!=null,"NOTES_HISTORY_REQUEST_MISSING");this.request=request;
            byte[] bytes=raw==null?null:raw.getBytes(StandardCharsets.UTF_8);
            need(bytes!=null&&bytes.length>0&&bytes.length<=BackgroundOwnedSingleTask.MAX_DUMP_BYTES,"PUBLIC_HISTORY_RAW_BOUND");
            this.raw=raw;census=PublicOwnGroupPhysicalFence.inspectRecents(raw);
            int begin=raw.indexOf(INTERNAL),end=raw.indexOf(VISIBLE);
            need(begin>=0&&end>begin&&begin==raw.lastIndexOf(INTERNAL)&&end==raw.lastIndexOf(VISIBLE),"PUBLIC_HISTORY_SECTIONS");
            String prefix=raw.substring(0,begin);hiddenField=prefix.contains("\nmHiddenTasks=");
            preamble=prefix.replaceAll("(?m)^mHiddenTasks=\\[[^\\r\\n]*\\]\\n","");
            String internal=raw.substring(begin+INTERNAL.length(),end),vis=raw.substring(end+VISIBLE.length());
            List<Matcher> heads=matches(HEAD,internal);Map<Integer,Row> parsed=new LinkedHashMap<Integer,Row>();
            Map<Integer,String> ts=new LinkedHashMap<Integer,String>();Map<String,Integer> tokenOwners=new HashMap<String,Integer>();
            need(!heads.isEmpty()&&heads.size()<=ProfileTaskPolicy.MAX_LEAVES,"PUBLIC_HISTORY_ROW_BOUND");
            for(int i=0;i<heads.size();i++){
                Matcher h=heads.get(i);int id=(int)decimal(h.group(4));PublicOwnGroupPhysicalFence.RecentRecord f=census.records.get(id);
                need(decimal(h.group(1))==i&&f!=null&&f.token.equals(h.group(3))&&f.label.equals(h.group(2)),"PUBLIC_HISTORY_ROW_IDENTITY");
                String body=internal.substring(h.end(),i+1<heads.size()?heads.get(i+1).start():internal.length());
                Row row=new Row(f,body);need(parsed.put(id,row)==null,"PUBLIC_HISTORY_DUPLICATE_ID");putToken(ts,tokenOwners,id,f.token);
            }
            need(parsed.keySet().equals(census.records.keySet()),"PUBLIC_HISTORY_MEMBERSHIP");
            List<VisibleRow> visibleRows=new ArrayList<VisibleRow>();List<Matcher> visibleHeads=matches(VHEAD,vis);
            for(int i=0;i<visibleHeads.size();i++){
                Matcher h=visibleHeads.get(i);need(decimal(h.group(1))==i,"PUBLIC_HISTORY_VISIBLE_ORDER");
                String body=vis.substring(h.end(),i+1<visibleHeads.size()?visibleHeads.get(i+1).start():vis.length());
                Matcher identity=one("^    id=([0-9]+) userId=([0-9]+) hasTask=(true|false) lastActiveTime=([0-9]+)$",body,"PUBLIC_HISTORY_VISIBLE_IDENTITY");
                int id=(int)decimal(identity.group(1));Row row=parsed.get(id);
                need(row!=null&&!row.visible&&row.fact.user==decimal(identity.group(2))&&row.lastActive==decimal(identity.group(4)),"PUBLIC_HISTORY_VISIBLE_DISAGREES");
                row.visible=true;row.hasTask="true".equals(identity.group(3));visibleRows.add(new VisibleRow(id,body));
            }
            for(Map.Entry<Integer,String> hidden:census.hiddenLabels.entrySet()){
                Matcher label=one("^Task\\{([0-9a-f]+) #([0-9]+) [^{}\\r\\n]+\\}$",hidden.getValue(),"PUBLIC_HISTORY_HIDDEN_LABEL");
                need(decimal(label.group(2))==hidden.getKey(),"PUBLIC_HISTORY_HIDDEN_ID");
                Row known=parsed.get(hidden.getKey());need(known==null||known.fact.label.equals(hidden.getValue()),"PUBLIC_HISTORY_HIDDEN_LABEL_DISAGREES");
                putToken(ts,tokenOwners,hidden.getKey(),label.group(1));
            }
            rows=Collections.unmodifiableMap(parsed);visible=Collections.unmodifiableList(visibleRows);tokens=Collections.unmodifiableMap(ts);
            requireIdentity();
        }
        private boolean notes(String text){
            return request.targetHint(text);
        }
        private void requireIdentity(){
            for(int id:request.recordedTaskIds)need(!census.allIds.contains(id),"NOTES_HISTORY_RECORDED_TASK_PRESENT");
            for(Row r:rows.values()){
                need(r.fact.uid!=request.targetUid&&!notes(r.fact.label+"\n"+r.body),"NOTES_HISTORY_TARGET_ALIAS_PRESENT");
                need(r.fact.display!=request.displayId&&!request.recordedTaskIds.contains(r.fact.root),"NOTES_HISTORY_RECORDED_LOCATION_PRESENT");
            }
            for(Map.Entry<Integer,String> h:census.hiddenLabels.entrySet())
                need(!request.recordedTaskIds.contains(h.getKey())&&!notes(h.getValue()),"NOTES_HISTORY_HIDDEN_TARGET_PRESENT");
        }
        private boolean exclude(int id){return false;}
        private String foreign(){
            StringBuilder out=new StringBuilder();append(out,preamble);append(out,"hidden_field="+hiddenField);
            for(Row r:rows.values())if(!exclude(r.fact.task)){append(out,"internal|"+r.fact.label);append(out,r.stable);}
            for(VisibleRow r:visible)if(!exclude(r.id)){append(out,"visible|"+r.id);append(out,r.stable);}
            for(Map.Entry<Integer,String> h:census.hiddenLabels.entrySet())if(!exclude(h.getKey()))append(out,"hidden|"+h.getValue());
            return out.toString();
        }
        public void requireSameForeign(Snapshot after,long ageBudget){
            need(after!=null&&ageBudget>=0&&request.originalsSha256.equals(after.request.originalsSha256),"NOTES_HISTORY_AGE_INTERVAL");requireIdentity();after.requireIdentity();
            need(foreign().equals(after.foreign()),"NOTES_HISTORY_FOREIGN_CHANGED");
            for(Row r:rows.values())if(!exclude(r.fact.task)){
                Row later=after.rows.get(r.fact.task);
                need(later!=null&&later.lastActive==r.lastActive&&later.age>=r.age&&later.age-r.age<=ageBudget,
                        "NOTES_HISTORY_AGE_REVERSED_OR_JUMPED");
            }
        }
        public Map<String,Object> evidence(){
            requireIdentity();Map<String,Object> v=new LinkedHashMap<String,Object>();
            v.put("schema","hepta.personal-notes-preserved-history.v1");v.put("complete",true);
            v.put("target_package",PublicPersonalNotesAbsenceRecovery.PACKAGE);v.put("target_user_id",0);v.put("target_full_uid",request.targetUid);
            v.put("recorded_task_ids",new JSONArray(request.recordedTaskIds));v.put("recorded_display_id",request.displayId);
            v.put("recorded_owned_task_present",false);v.put("target_absent",true);
            v.put("raw_text",raw);v.put("raw_bytes",raw.getBytes(StandardCharsets.UTF_8).length);v.put("raw_sha256",census.rawSha256);
            v.put("foreign_history_sha256",ProfileIdentity.sha(foreign()));v.put("history_record_count",rows.size());
            v.put("hidden_label_count",census.hiddenLabels.size());v.put("serialized_task_ids_grant_authority",false);
            v.put("whole_personal_profile_empty_claimed",false);return Collections.unmodifiableMap(v);
        }
    }
    private static void putToken(Map<Integer,String> ids,Map<String,Integer> owners,int id,String token){
        String previous=ids.put(id,token);Integer other=owners.put(token,id);
        need((previous==null||previous.equals(token))&&(other==null||other.intValue()==id),"NOTES_HISTORY_TOKEN_REUSED");
    }
    public static Snapshot absence(String raw,PublicPersonalNotesAbsenceRecovery.Request request)throws Exception{
        return new Snapshot(raw,request);
    }
    public static void requireSameEvidence(JSONObject first,JSONObject last,PublicPersonalNotesAbsenceRecovery.Request request,long ageBudget)throws Exception{
        need(first!=null&&last!=null,"NOTES_HISTORY_EVIDENCE_MISSING");
        Snapshot a=absence(first.getString("raw_text"),request),b=absence(last.getString("raw_text"),request);
        need(PublicProfileAbsenceRecovery.same(first,new JSONObject(a.evidence()))
                &&PublicProfileAbsenceRecovery.same(last,new JSONObject(b.evidence())),"NOTES_HISTORY_EVIDENCE_DIFFERS");
        a.requireSameForeign(b,ageBudget);
    }
}
