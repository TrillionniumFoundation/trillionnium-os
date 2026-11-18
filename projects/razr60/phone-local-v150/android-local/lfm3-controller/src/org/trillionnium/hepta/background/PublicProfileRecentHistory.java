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

/** Public-mode-only preservation of dormant foreign history. No task mutation.
 * The private dedicated-profile admission remains a separate, stricter policy.
 * Live user-10 root/leaf admission must additionally use the original Binder census.
 */
public final class PublicProfileRecentHistory {
    public static final String SCHEMA="hepta.public-profile-preserved-recents.v1";
    private static final String INTERNAL="  Recent tasks:\n",VISIBLE="  Visible recent tasks (most recent first):\n";
    private static final Pattern HEAD=Pattern.compile("(?m)^  \\* Recent #([0-9]+): (Task\\{([0-9a-f]+) #([0-9]+) [^{}\\r\\n]+\\})$");
    private static final Pattern VHEAD=Pattern.compile("(?m)^  \\* RecentTaskInfo #([0-9]+):[ \\t]*$");
    private static final Pattern AGE=Pattern.compile("(?m)^    lastActiveTime=(0|[1-9][0-9]*) \\(inactive for (0|[1-9][0-9]*)s\\)$");
    private static final Set<Integer> NONE=Collections.emptySet();
    private PublicProfileRecentHistory(){}
    private static void need(boolean ok,String code){if(!ok)throw new IllegalArgumentException(code);}
    private static long decimal(String value){try{need(value!=null&&value.matches("0|[1-9][0-9]*"),"PUBLIC_HISTORY_INTEGER");return Long.parseLong(value);}
        catch(NumberFormatException bad){throw new IllegalArgumentException("PUBLIC_HISTORY_INTEGER_RANGE",bad);}}
    private static Matcher one(Pattern pattern,String text,String code){Matcher m=pattern.matcher(text);need(m.find(),code);Matcher result=pattern.matcher(text);need(result.find()&&!m.find(),code);return result;}
    private static Matcher one(String regex,String text,String code){return one(Pattern.compile(regex,Pattern.MULTILINE),text,code);}
    private static List<Matcher> matches(Pattern pattern,String text){List<Matcher> out=new ArrayList<Matcher>();Matcher scan=pattern.matcher(text);
        while(scan.find()){Matcher saved=pattern.matcher(text);need(saved.find(scan.start()),"PUBLIC_HISTORY_PATTERN");out.add(saved);}return out;}
    private static boolean targetPackage(String text,ProfileTarget target){return text!=null&&Pattern.compile("(?<![A-Za-z0-9_.])"+Pattern.quote(target.packageName)+"(?=$|[^A-Za-z0-9_.])").matcher(text).find();}
    private static boolean uidText(String text,int uid){return text!=null&&Pattern.compile("(?<![0-9])"+uid+"(?=$|[^0-9])").matcher(text).find();}
    private static boolean targetUidText(String text,ProfileTarget target){
        String formatted="u"+target.profile.userId+"a"+(target.fullUid%100000-10000);
        return uidText(text,target.fullUid)||Pattern.compile("(?<![A-Za-z0-9])"+Pattern.quote(formatted)+"(?=$|[^A-Za-z0-9])").matcher(text).find();
    }
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
    /** Full raw read and derived facts. It is observation only, never cleanup authority. */
    public static final class Snapshot {
        private final String raw,preamble;private final boolean hiddenField;
        private final ProfileTarget target;
        private final PublicOwnGroupPhysicalFence.RecentCensus census;
        private final Map<Integer,Row> rows;
        private final List<VisibleRow> visible;
        private final Map<Integer,String> tokens;
        private Snapshot(String raw,ProfileTarget target)throws Exception{
            need(target!=null&&target.profile.userId==10&&target.profile.parentUserId==0&&ProfileTarget.CTRIP.equals(target.packageName),"PUBLIC_HISTORY_TARGET");
            byte[] bytes=raw==null?null:raw.getBytes(StandardCharsets.UTF_8);
            need(bytes!=null&&bytes.length>0&&bytes.length<=BackgroundOwnedSingleTask.MAX_DUMP_BYTES,"PUBLIC_HISTORY_RAW_BOUND");
            this.raw=raw;this.target=target;census=PublicOwnGroupPhysicalFence.inspectRecents(raw);
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
        }
        private void requireForeign(Set<Integer> owned){
            for(Row r:rows.values())if(r.fact.user==target.profile.userId&&!owned.contains(r.fact.task)){
                // All producer identity fields remain in the stable body. A package/UID
                // hint in ANY of them vetoes the foreign classification.
                need(r.fact.uid!=target.fullUid&&!targetPackage(r.fact.label+"\n"+r.body,target)
                        &&!targetUidText(r.fact.label+"\n"+r.body,target),"PUBLIC_HISTORY_TARGET_RECENT_PRESENT");
                need(r.fact.uid/100000==target.profile.userId&&r.fact.uid%100000>=10000&&component(r.fact.base)&&component(r.fact.activity)
                        &&!r.fact.affinity.isEmpty()&&r.fact.affinity.startsWith(r.fact.uid+":")
                        &&r.affinityLine.equals(r.fact.affinity),"PUBLIC_HISTORY_FOREIGN_IDENTITY_AMBIGUOUS");
                need("[]".equals(r.activities)&&(!r.visible||!r.hasTask),"PUBLIC_HISTORY_FOREIGN_RECENT_ACTIVE");
            }
            for(Map.Entry<Integer,String> h:census.hiddenLabels.entrySet())if(!owned.contains(h.getKey())&&!rows.containsKey(h.getKey())){
                Matcher affinity=one("(?:^| )A=([0-9]+):([^ }]+)",h.getValue(),"PUBLIC_HISTORY_DETACHED_HIDDEN_USER_UNKNOWN");
                long uid=decimal(affinity.group(1));need(uid<=Integer.MAX_VALUE,"PUBLIC_HISTORY_HIDDEN_UID");
                // A detached profile label has no Activities/UID census. It is not
                // promoted to a proven dormant foreign task; preserve and refuse it.
                need(uid/100000!=target.profile.userId,"PUBLIC_HISTORY_DETACHED_PROFILE_HIDDEN_UNKNOWN");
                need(uid!=target.fullUid,"PUBLIC_HISTORY_TARGET_HIDDEN_PRESENT");
            }
        }
        private String history(Set<Integer> owned){StringBuilder out=new StringBuilder();append(out,preamble);
            append(out,"hidden_field="+hiddenField);
            for(Row r:rows.values())if(!owned.contains(r.fact.task)){append(out,"internal|"+r.fact.label);append(out,r.stable);}
            for(VisibleRow r:visible)if(!owned.contains(r.id)){append(out,"visible|"+r.id);append(out,r.stable);}
            for(Map.Entry<Integer,String> h:census.hiddenLabels.entrySet())if(!owned.contains(h.getKey()))append(out,"hidden|"+h.getValue());
            return out.toString();}
        private void sameHistory(Snapshot after,Set<Integer> own,long maxAgeAdvance){
            need(maxAgeAdvance>=0,"PUBLIC_HISTORY_AGE_INTERVAL");
            need(after!=null&&target.same(after.target)&&history(own).equals(after.history(own)),"PUBLIC_HISTORY_CHANGED");
            for(Row r:rows.values())if(!own.contains(r.fact.task)){
                Row later=after.rows.get(r.fact.task);need(later!=null&&later.lastActive==r.lastActive&&later.age>=r.age
                        &&later.age-r.age<=maxAgeAdvance,"PUBLIC_HISTORY_AGE_REVERSED_OR_JUMPED");}
        }
        public void requireSame(Snapshot after){requireSame(after,Long.MAX_VALUE);}
        public void requireSame(Snapshot after,long maxAgeAdvance){requireForeign(NONE);after.requireForeign(NONE);sameHistory(after,NONE,maxAgeAdvance);}
        public Map<String,Object> evidence(){requireForeign(NONE);Map<String,Object> out=new LinkedHashMap<String,Object>();
            out.put("schema",SCHEMA);out.put("complete",true);out.put("target_sha256",target.sha256);out.put("target_user_id",target.profile.userId);
            out.put("target_full_uid",target.fullUid);out.put("target_absent",true);out.put("foreign_dormant_history_preserved",true);
            List<Map<String,Object>> foreign=new ArrayList<Map<String,Object>>();for(Row r:rows.values())if(r.fact.user==target.profile.userId)foreign.add(r.evidence());
            out.put("profile_empty",foreign.isEmpty());out.put("foreign_dormant_records",foreign);out.put("raw_text",raw);
            out.put("raw_bytes",raw.getBytes(StandardCharsets.UTF_8).length);out.put("raw_sha256",census.rawSha256);
            out.put("normalized_history_sha256",ProfileIdentity.sha(history(NONE)));out.put("history_record_count",rows.size());
            out.put("hidden_label_count",census.hiddenLabels.size());out.put("serialized_task_ids_grant_authority",false);
            return Collections.unmodifiableMap(out);}
    }
    private static void putToken(Map<Integer,String> ids,Map<String,Integer> owners,int id,String token){
        String previous=ids.put(id,token);Integer other=owners.put(token,id);
        need((previous==null||previous.equals(token))&&(other==null||other.intValue()==id),"PUBLIC_HISTORY_TOKEN_REUSED");}
    public static Snapshot absence(String raw,ProfileTarget target)throws Exception{Snapshot out=new Snapshot(raw,target);out.requireForeign(NONE);return out;}
    /** Reparse both complete raw inputs. No serialized flag or hash substitutes for a census. */
    public static void requireSameEvidence(JSONObject first,JSONObject last,ProfileTarget target)throws Exception{
        requireSameEvidence(first,last,target,Long.MAX_VALUE);
    }
    public static void requireSameEvidence(JSONObject first,JSONObject last,ProfileTarget target,long maxAgeAdvanceSeconds)throws Exception{
        need(first!=null&&last!=null,"PUBLIC_HISTORY_EVIDENCE_MISSING");
        Snapshot a=absence(first.getString("raw_text"),target),b=absence(last.getString("raw_text"),target);
        need(canonical(first).equals(canonical(new JSONObject(a.evidence())))&&canonical(last).equals(canonical(new JSONObject(b.evidence()))),"PUBLIC_HISTORY_EVIDENCE_DIFFERS");
        a.requireSame(b,maxAgeAdvanceSeconds);
    }
    private static String canonical(Object value)throws Exception{
        if(value==null||value==JSONObject.NULL)return "null";
        if(value instanceof JSONObject){JSONObject object=(JSONObject)value;List<String> keys=new ArrayList<String>();java.util.Iterator<String> it=object.keys();while(it.hasNext())keys.add(it.next());Collections.sort(keys);
            StringBuilder out=new StringBuilder("{");for(String k:keys){if(out.length()>1)out.append(',');out.append(JSONObject.quote(k)).append(':').append(canonical(object.get(k)));}return out.append('}').toString();}
        if(value instanceof JSONArray){JSONArray a=(JSONArray)value;StringBuilder out=new StringBuilder("[");for(int i=0;i<a.length();i++){if(i>0)out.append(',');out.append(canonical(a.get(i)));}return out.append(']').toString();}
        if(value instanceof String)return JSONObject.quote((String)value);
        need(value instanceof Boolean||value instanceof Integer||value instanceof Long,"PUBLIC_HISTORY_JSON_TYPE");return value.toString();
    }
    /** In-memory public custody. Serialized task IDs never construct this owner.
     * Caller must first run the unchanged actual Binder/cookie/UID task validators. */
    public static final class Baseline implements ProfileOwnedTask.PublicRecentHistory {
        private final Snapshot first;private Snapshot last;private final Set<Integer> originalIds;
        private final Set<String> originalTokens;private final Map<Integer,String> ownedTokens=new LinkedHashMap<Integer,String>();
        private final Map<Integer,BackgroundOwnedSingleTask.Task> retained=new LinkedHashMap<Integer,BackgroundOwnedSingleTask.Task>();
        private final long firstAt;private long lastAt;private boolean failed;private String failure;
        public Baseline(Snapshot admitted,long elapsed){need(admitted!=null&&elapsed>=0,"PUBLIC_HISTORY_BASELINE_MISSING");admitted.requireForeign(NONE);first=admitted;last=admitted;firstAt=lastAt=elapsed;
            originalIds=Collections.unmodifiableSet(new LinkedHashSet<Integer>(admitted.census.allIds));originalTokens=Collections.unmodifiableSet(new HashSet<String>(admitted.tokens.values()));}
        public synchronized Set<Integer> originalIds(){return originalIds;}
        public synchronized Set<Integer> observedIds(){return Collections.unmodifiableSet(new LinkedHashSet<Integer>(last.census.allIds));}
        public synchronized void requireTargetAbsent(String raw,ProfileTarget target,long elapsed)throws Exception{
            try{requireCurrent(elapsed);Snapshot next=absence(raw,target);first.sameHistory(next,NONE,ageBudget(firstAt,elapsed));
                last.sameHistory(next,NONE,ageBudget(lastAt,elapsed));last=next;lastAt=elapsed;}
            catch(Exception error){failed=true;failure=error.getMessage();throw error;}
        }
        public synchronized void observe(String raw,ProfileTarget target,BackgroundOwnedSingleTask.Task root,BackgroundOwnedSingleTask.Task leaf,int display,long elapsed)throws Exception{
            try{
            requireCurrent(elapsed);need(first.target.same(target)&&display>1,"PUBLIC_HISTORY_CUSTODY_SCOPE");Snapshot next=new Snapshot(raw,target);Set<Integer> own=new LinkedHashSet<Integer>();
            if(root!=null){claim(root,target,false,display);own.add(root.id);}
            if(leaf!=null){need(root!=null&&leaf.parent==root.id,"PUBLIC_HISTORY_OWNED_PARENT");claim(leaf,target,true,display);own.add(leaf.id);}
            for(int id:own){BackgroundOwnedSingleTask.Task task=retained.get(id);PublicOwnGroupPhysicalFence.RecentRecord row=next.census.records.get(id);
                if(row!=null){need(row.user==task.user&&row.uid==task.uid&&row.display==display
                        &&row.root==(task.parent<0?task.id:task.parent),"PUBLIC_HISTORY_OWNED_RECENT_TUPLE");
                    if(task.user==target.profile.userId)need(targetPackage(row.base,target)&&targetPackage(row.activity,target),"PUBLIC_HISTORY_OWNED_RECENT_PACKAGE");
                }
                String token=next.tokens.get(id);if(token!=null){need(!originalTokens.contains(token),"PUBLIC_HISTORY_OWNED_TOKEN_PREEXISTED");
                    String prior=ownedTokens.get(id);need(prior==null?row!=null:prior.equals(token),"PUBLIC_HISTORY_OWNED_TOKEN_CHANGED");
                    for(Map.Entry<Integer,String> entry:ownedTokens.entrySet())need(entry.getKey()==id||!entry.getValue().equals(token),"PUBLIC_HISTORY_OWNED_TOKEN_REUSED");
                    ownedTokens.put(id,token);}
            }
            next.requireForeign(own);first.sameHistory(next,own,ageBudget(firstAt,elapsed));last.sameHistory(next,own,ageBudget(lastAt,elapsed));last=next;lastAt=elapsed;
            }catch(Exception error){failed=true;failure=error.getMessage();throw error;}
        }
        private void requireCurrent(long elapsed){need(!failed,"PUBLIC_HISTORY_PREVIOUS_REFUSAL");need(elapsed>=lastAt,"PUBLIC_HISTORY_CLOCK_REVERSED");}
        private static long ageBudget(long before,long after){need(before>=0&&after>=before,"PUBLIC_HISTORY_CLOCK_REVERSED");return (after-before)/1000+2;}
        private void claim(BackgroundOwnedSingleTask.Task t,ProfileTarget target,boolean leaf,int display){
            need(t.id>0&&!originalIds.contains(t.id)&&t.token!=null&&t.display==display
                    &&(leaf?t.user==target.profile.userId&&t.uid==target.fullUid:t.user==0&&t.parent==-1),"PUBLIC_HISTORY_OWNED_CLAIM_INVALID");
            BackgroundOwnedSingleTask.Task old=retained.get(t.id);
            need(old==null||old.user==t.user&&old.uid==t.uid&&old.parent==t.parent&&old.display==t.display&&Objects.equals(old.token,t.token),"PUBLIC_HISTORY_OWNED_BINDER_CHANGED");
            retained.put(t.id,t);
        }
        public synchronized boolean ownedAbsent(){if(failed)return false;for(int id:retained.keySet())if(last.census.allIds.contains(id))return false;return true;}
        public synchronized Map<String,Object> evidence(){Map<String,Object> out=new LinkedHashMap<String,Object>();
            out.put("schema","hepta.public-profile-history-custody.v1");out.put("target_sha256",first.target.sha256);
            out.put("foreign_dormant_history_preserved",!failed);out.put("history_refusal_latched",failed);out.put("history_refusal_reason",failure);
            out.put("baseline_elapsed_ms",firstAt);out.put("current_elapsed_ms",lastAt);
            out.put("baseline_raw_sha256",first.census.rawSha256);out.put("current_raw_sha256",last.census.rawSha256);
            out.put("nonowned_history_sha256",ProfileIdentity.sha(first.history(retained.keySet())));
            out.put("baseline_task_ids",new ArrayList<Integer>(originalIds));out.put("owned_task_ids",new ArrayList<Integer>(retained.keySet()));
            out.put("owned_target_absent",ownedAbsent());out.put("serialized_task_ids_grant_authority",false);return Collections.unmodifiableMap(out);}
    }
}
