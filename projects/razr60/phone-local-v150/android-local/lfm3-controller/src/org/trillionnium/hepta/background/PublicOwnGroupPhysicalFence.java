package org.trillionnium.hepta.background;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Read-only Android-16 dump projection for Razr's physical displays 0 and 1.
 * Activity/Window labels are observations, never Binder action authority. Every
 * section is read in full with a strict bound; a partial/unknown shape refuses.
 * This is the explicit new-scope diagnostic/permission-initialization audit;
 * comparing its entire hash is deliberately NOT the product's continuous
 * admission policy while a user operates the physical screens. All hidden
 * labels/order are retained, including detached references of unknown owner.
 * A dedicated positive target user is omitted only from internal/visible
 * recents (its actual ownership is guarded independently). Target user 0 never
 * causes all personal tasks/history to be omitted. */
public final class PublicOwnGroupPhysicalFence {
    public static final String SCHEMA="hepta.public-own-group.physical-audit.v1";
    private static final String CONTROLLER="org.trillionnium.hepta.local";
    private static final int MAX=2*1024*1024;
    private PublicOwnGroupPhysicalFence(){}
    public static final class DisplayFacts {
        public final int id,type,state,rotation,width,height;
        public final String uniqueId;
        public DisplayFacts(int id,String uniqueId,int type,int state,int rotation,int width,int height){
            need((id==0||id==1)&&uniqueId!=null&&uniqueId.matches("local:[0-9]+")&&type==1
                    &&(state==1||state==2)&&rotation>=0&&rotation<=3&&width>0&&height>0,"PHYSICAL_DISPLAY_IDENTITY_INVALID");
            this.id=id;this.uniqueId=uniqueId;this.type=type;this.state=state;this.rotation=rotation;this.width=width;this.height=height;
        }
        String data(){return id+"|"+uniqueId+"|"+type+"|"+state+"|"+rotation+"|"+width+"|"+height;}
    }
    private static void need(boolean ok,String code){if(!ok)throw new IllegalArgumentException(code);}
    private static Matcher one(String regex,String text,String code){
        Matcher m=Pattern.compile(regex,Pattern.MULTILINE).matcher(text);need(m.find(),code);int a=m.start(),b=m.end();
        need(!m.find(),code);m.reset();need(m.find()&&m.start()==a&&m.end()==b,code);return m;
    }
    private static List<Matcher> matches(String regex,String text){
        List<Matcher> out=new ArrayList<Matcher>();Pattern p=Pattern.compile(regex,Pattern.MULTILINE);Matcher scan=p.matcher(text);
        while(scan.find()){Matcher row=p.matcher(text);row.region(scan.start(),scan.end());need(row.find(),"PHYSICAL_MATCH_FAILED");out.add(row);}
        return out;
    }
    private static String checked(String text,String header){
        need(text!=null&&text.length()>0&&text.getBytes(StandardCharsets.UTF_8).length<=MAX&&text.indexOf('\0')<0
                &&text.startsWith(header+"\n")&&!Pattern.compile("dump timed out|permission denial|exception while dumping|output truncated",
                Pattern.CASE_INSENSITIVE).matcher(text).find(),"PHYSICAL_DUMP_INCOMPLETE");return text;
    }
    private static int n(String value){try{return Integer.parseInt(value);}catch(Exception e){throw new IllegalArgumentException("PHYSICAL_NUMBER_INVALID",e);}}
    private static String component(String value){
        need(value!=null&&value.matches("[A-Za-z0-9_.$]+/[A-Za-z0-9_.$]+"),"PHYSICAL_COMPONENT_INVALID");
        int slash=value.indexOf('/');String pkg=value.substring(0,slash),cls=value.substring(slash+1);return pkg+"/"+(cls.startsWith(".")?pkg+cls:cls);
    }
    private static String optional(String regex,String text){List<Matcher> rows=matches(regex,text);need(rows.size()<=1,"PHYSICAL_FIELD_AMBIGUOUS");return rows.isEmpty()?"":rows.get(0).group(1);}
    private static void append(StringBuilder b,String value){b.append(value.length()).append(':').append(value);}
    private static final class Activity {
        final String token,component;final int user,task;
        Activity(String token,int user,String component,int task){this.token=token;this.user=user;this.component=component(component);this.task=task;}
        String data(){return token+"|"+user+"|"+component+"|"+task;}
    }
    private static final class Hierarchy {
        final Map<Integer,StringBuilder> rows=new LinkedHashMap<Integer,StringBuilder>();
        final Map<Integer,List<Activity>> activities=new LinkedHashMap<Integer,List<Activity>>();
    }
    private static Hierarchy activities(String raw,int targetUser){
        String text=checked(raw,"ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)");
        String end="\nActivityTaskSupervisor state:\n";need(text.indexOf(end)>=0&&text.indexOf(end)==text.lastIndexOf(end),"PHYSICAL_HIERARCHY_END_MISSING");
        Hierarchy result=new Hierarchy();Set<Integer> ids=new HashSet<Integer>();List<int[]> stack=new ArrayList<int[]>();int display=-1;
        for(String line:text.substring(0,text.indexOf(end)).split("\n")){
            if(line.startsWith("Display #")){
                Matcher m=one("^Display #([0-9]+) \\(activities from top to bottom\\):$",line,"PHYSICAL_ACTIVITY_DISPLAY_INVALID");
                display=n(m.group(1));need(!result.rows.containsKey(display),"PHYSICAL_ACTIVITY_DISPLAY_DUPLICATE");
                result.rows.put(display,new StringBuilder());result.activities.put(display,new ArrayList<Activity>());stack.clear();
            }else if(line.matches("\\s*\\* Task.*")){
                Matcher m=one("^( +)\\* Task\\{([0-9a-f]+) #([0-9]+) ([^{}\\r\\n]+)\\}$",line,"PHYSICAL_TASK_INVALID");
                need(display>=0,"PHYSICAL_TASK_OUTSIDE_DISPLAY");int level=m.group(1).length(),task=n(m.group(3));String body=m.group(4);
                need(ids.add(task),"PHYSICAL_TASK_DUPLICATE");int user=n(one("(?:^| )U=([0-9]+)(?= |$)",body,"PHYSICAL_TASK_USER_MISSING").group(1));
                while(!stack.isEmpty()&&stack.get(stack.size()-1)[0]>=level)stack.remove(stack.size()-1);
                int parent=stack.isEmpty()?-1:stack.get(stack.size()-1)[1];
                String affinity=optional("(?:^| )A=([^\\s]+)",body),intent=optional("(?:^| )I=([^\\s]+)",body);
                if(display==0||display==1)need((targetUser==0||user!=targetUser)&&!affinity.endsWith(":"+CONTROLLER)&&!intent.startsWith(CONTROLLER+"/"),"PHYSICAL_BACKGROUND_TASK_ESCAPED");
                append(result.rows.get(display),"task|"+m.group(2)+"|"+task+"|"+parent+"|"+user+"|"+affinity+"|"+intent);
                stack.add(new int[]{level,task,user});
            }else if(line.matches("\\s*\\* Hist\\b.*")){
                Matcher m=one("^( +)\\* Hist +#[0-9]+: ActivityRecord\\{([0-9a-f]+) u([0-9]+) ([A-Za-z0-9_.$]+/[A-Za-z0-9_.$]+) t([0-9]+)(?: f\\})?(?: isExiting)?\\}$",line,"PHYSICAL_ACTIVITY_INVALID");
                need(display>=0&&!stack.isEmpty(),"PHYSICAL_ACTIVITY_OUTSIDE_TASK");int[] parent=stack.get(stack.size()-1);int user=n(m.group(3)),task=n(m.group(5));
                need(m.group(1).length()>parent[0]&&task==parent[1]&&user==parent[2],"PHYSICAL_ACTIVITY_PARENT_INVALID");
                Activity activity=new Activity(m.group(2),user,m.group(4),task);
                if(display==0||display==1)need((targetUser==0||user!=targetUser)&&!activity.component.startsWith(CONTROLLER+"/"),"PHYSICAL_BACKGROUND_ACTIVITY_ESCAPED");
                result.activities.get(display).add(activity);append(result.rows.get(display),"activity|"+activity.data());
            }
        }
        need(result.rows.containsKey(0)&&result.rows.containsKey(1)&&!ids.isEmpty(),"PHYSICAL_BOTH_HIERARCHIES_REQUIRED");return result;
    }
    private static Map<Integer,String> windows(String raw,Hierarchy hierarchy,Map<Integer,DisplayFacts> displays,int targetUser){
        String text=checked(raw,"WINDOW MANAGER DISPLAY CONTENTS (dumpsys window displays)");
        List<Matcher> heads=matches("^  Display: mDisplayId=([0-9]+)\\b[^\\r\\n]*$",text);Set<Integer> seen=new HashSet<Integer>();
        Map<Integer,String> out=new LinkedHashMap<Integer,String>();
        for(int i=0;i<heads.size();i++){
            Matcher h=heads.get(i);int display=n(h.group(1));need(seen.add(display),"PHYSICAL_WINDOW_DISPLAY_DUPLICATE");
            if(display!=0&&display!=1)continue;
            String body=text.substring(h.end(),i+1<heads.size()?heads.get(i+1).start():text.length());
            String focus=one("^  mCurrentFocus=([^\\r\\n]+)$",body,"PHYSICAL_WINDOW_FOCUS_MISSING").group(1);
            String app=one("^  mFocusedApp=([^\\r\\n]+)$",body,"PHYSICAL_FOCUSED_APP_MISSING").group(1);
            if("null".equals(focus)||"null".equals(app))need(focus.equals(app)&&displays.get(display).state==1,"PHYSICAL_NULL_FOCUS_NOT_OFF");
            else{
                Matcher w=one("^Window\\{([0-9a-f]+) u([0-9]+) ([^{}\\r\\n]+)\\}$",focus,"PHYSICAL_FOCUS_INVALID");
                Matcher a=one("^ActivityRecord\\{([0-9a-f]+) u([0-9]+) ([A-Za-z0-9_.$]+/[A-Za-z0-9_.$]+) t([0-9]+)(?: f\\})?(?: isExiting)?\\}$",app,"PHYSICAL_FOCUSED_ACTIVITY_INVALID");
                need((targetUser==0||n(w.group(2))!=targetUser)&&!w.group(3).contains(CONTROLLER+"/"),"PHYSICAL_BACKGROUND_FOCUS_ESCAPED");
                Activity expected=new Activity(a.group(1),n(a.group(2)),a.group(3),n(a.group(4)));int count=0;
                for(Activity actual:hierarchy.activities.get(display))if(actual.data().equals(expected.data()))count++;
                need(count==1,"PHYSICAL_FOCUSED_ACTIVITY_NOT_IN_DISPLAY");
            }
            StringBuilder value=new StringBuilder();append(value,focus);append(value,app);
            for(String key:Arrays.asList("mInputMethodWindow","mImeInputTarget","mImeLayeringTarget","mImeControlTarget"))
                append(value,key+"="+optional("^  "+key+"=([^\\r\\n]+)$",body));
            out.put(display,value.toString());
        }
        need(out.size()==2,"PHYSICAL_BOTH_FOCI_REQUIRED");return out;
    }
    private static final class Recent {
        int task,user,uid,root,display;String token,affinity,activity,base,flags,label;
        String data(){return task+"|"+token+"|"+affinity+"|"+user+"|"+uid+"|"+root+"|"+display+"|"+activity+"|"+base+"|"+flags;}
    }
    /** Complete read-only membership and actual UID facts. These values never
     * authorize task removal; detached hidden labels retain unknown ownership. */
    public static final class RecentRecord {
        public final int task,user,uid,root,display;
        public final String token,affinity,activity,base,flags,label,identity;
        private RecentRecord(Recent row){task=row.task;user=row.user;uid=row.uid;root=row.root;display=row.display;
            token=row.token;affinity=row.affinity;activity=row.activity;base=row.base;flags=row.flags;label=row.label;
            identity=row.data()+"|"+label;}
    }
    private static final class RecentFact {
        final int task;final String value;
        RecentFact(int task,String value){this.task=task;this.value=value;}
    }
    public static final class RecentCensus {
        public final Map<Integer,RecentRecord> records;
        public final Map<Integer,String> hiddenLabels;
        public final Set<Integer> allIds;
        public final String rawSha256;
        private final String projection;
        private final List<RecentFact> facts;
        private RecentCensus(String projection,Map<Integer,Recent> rows,Map<Integer,String> hidden,List<RecentFact> facts,String raw){
            this.projection=projection;Map<Integer,RecentRecord> copy=new LinkedHashMap<Integer,RecentRecord>();
            for(Map.Entry<Integer,Recent> entry:rows.entrySet())copy.put(entry.getKey(),new RecentRecord(entry.getValue()));
            records=Collections.unmodifiableMap(copy);hiddenLabels=Collections.unmodifiableMap(new LinkedHashMap<Integer,String>(hidden));
            Set<Integer> ids=new java.util.LinkedHashSet<Integer>(rows.keySet());ids.addAll(hidden.keySet());allIds=Collections.unmodifiableSet(ids);
            this.facts=Collections.unmodifiableList(new ArrayList<RecentFact>(facts));
            rawSha256=ProfileIdentity.sha(raw.getBytes(StandardCharsets.UTF_8));
        }
        String historyExcept(Set<Integer> owned){
            need(owned!=null,"RECENT_HISTORY_OWNED_IDS_MISSING");StringBuilder out=new StringBuilder();
            for(RecentFact fact:facts)if(!owned.contains(fact.task))append(out,fact.value);
            return out.toString();
        }
    }
    public static RecentCensus inspectRecents(String raw){return recents(raw,0);}
    private static Recent label(String label){
        Matcher m=one("^Task\\{([0-9a-f]+) #([0-9]+) ([^{}\\r\\n]+)\\}$",label,"PHYSICAL_RECENT_LABEL_INVALID");
        Recent r=new Recent();r.token=m.group(1);r.task=n(m.group(2));r.affinity=optional("(?:^| )A=([^\\s]+)",m.group(3));r.label=label;return r;
    }
    private static String[] intent(String value){
        if("null".equals(value))return new String[]{"null","null"};
        String comp=optional("(?:^|[ {])cmp=([^\\s}]+)",value),flags=optional("(?:^|[ {])flg=0x([0-9a-fA-F]+)(?= |}|$)",value);
        return new String[]{comp.isEmpty()?"null":component(comp),flags.isEmpty()?"0":Long.toHexString(Long.parseLong(flags,16))};
    }
    private static int uid(String value){
        if(value.matches("[0-9]+"))return n(value);Matcher m=one("^u([0-9]+)(ai|a|s|i)([0-9]+)$",value,"PHYSICAL_RECENT_UID_INVALID");
        long out=(long)n(m.group(1))*100000+("a".equals(m.group(2))?10000:"ai".equals(m.group(2))?90000:"i".equals(m.group(2))?99000:0)+n(m.group(3));
        need(out<=Integer.MAX_VALUE,"PHYSICAL_RECENT_UID_INVALID");return (int)out;
    }
    private static RecentCensus recents(String raw,int targetUser){
        String text=checked(raw,"ACTIVITY MANAGER RECENT TASKS (dumpsys activity recents)");
        // Reuse the existing complete recent-task membership parser as an
        // independent fence before the richer stable-identity projection.
        try{ProfileTaskPolicy.Recents.parse(text);}catch(Exception e){throw new IllegalArgumentException("PHYSICAL_RECENTS_MEMBERSHIP_INVALID",e);}
        String a="  Recent tasks:\n",b="  Visible recent tasks (most recent first):\n";
        need(text.indexOf(a)>=0&&text.indexOf(a)==text.lastIndexOf(a)&&text.indexOf(b)>text.indexOf(a)&&text.indexOf(b)==text.lastIndexOf(b),"PHYSICAL_RECENTS_SECTIONS_INCOMPLETE");
        String pre=text.substring(0,text.indexOf(a)),internal=text.substring(text.indexOf(a)+a.length(),text.indexOf(b)),visible=text.substring(text.indexOf(b)+b.length());
        String[] lines=pre.split("\n");need(lines.length==5||lines.length==6,"PHYSICAL_RECENTS_PREAMBLE_INVALID");
        need(lines[1].matches("mRecentsUid=[0-9]+")&&lines[2].matches("mRecentsComponent=ComponentInfo\\{[^{}\\r\\n]+\\}")
                &&lines[3].matches("mFreezeTaskListReordering=(true|false)")&&lines[4].matches("mFreezeTaskListReorderingPendingTimeout=(true|false)"),"PHYSICAL_RECENTS_PREAMBLE_INVALID");
        Map<Integer,Recent> rows=new LinkedHashMap<Integer,Recent>();StringBuilder out=new StringBuilder();List<RecentFact> facts=new ArrayList<RecentFact>();
        for(int i=1;i<5;i++){append(out,lines[i]);facts.add(new RecentFact(-1,lines[i]));}
        List<Matcher> heads=matches("^  \\* Recent #([0-9]+): (Task\\{[^{}\\r\\n]+\\})$",internal);
        need(!heads.isEmpty()&&internal.substring(0,heads.get(0).start()).trim().isEmpty(),"PHYSICAL_INTERNAL_RECENTS_MISSING");
        for(int i=0;i<heads.size();i++){
            Matcher h=heads.get(i);need(n(h.group(1))==i,"PHYSICAL_RECENTS_INDICES_INCOMPLETE");
            String body=internal.substring(h.end(),i+1<heads.size()?heads.get(i+1).start():internal.length());Recent r=label(h.group(2));
            Matcher who=one("^    userId=([0-9]+) effectiveUid=([^ ]+) .*$",body,"PHYSICAL_RECENT_USER_MISSING");r.user=n(who.group(1));r.uid=uid(who.group(2));
            Matcher task=one("^    taskId=([0-9]+) rootTaskId=([0-9]+)$",body,"PHYSICAL_RECENT_ROOT_MISSING");
            need(n(task.group(1))==r.task&&r.uid/100000==r.user,"PHYSICAL_RECENT_IDENTITY_DISAGREES");r.root=n(task.group(2));
            one("^    Activities=(\\[[^\\r\\n]*\\])$",body,"PHYSICAL_RECENT_ACTIVITIES_MISSING");
            String activity=one("^    mActivityComponent=([^\\r\\n]+)$",body,"PHYSICAL_RECENT_COMPONENT_MISSING").group(1);
            r.activity="null".equals(activity)?"null":component(activity);
            r.display=n(one("^    lastDisplayId=(-?[0-9]+)[ \\t\\r\\n]*\\z",body,"PHYSICAL_RECENT_DISPLAY_MISSING").group(1));
            String[] in=intent(one("^    intent=(\\{[^\\r\\n]*\\}|null)$",body,"PHYSICAL_RECENT_INTENT_MISSING").group(1));r.base=in[0];r.flags=in[1];
            need(rows.put(r.task,r)==null,"PHYSICAL_RECENT_DUPLICATE");if(targetUser==0||r.user!=targetUser){
                String fact="internal|"+r.data();append(out,fact);facts.add(new RecentFact(r.task,fact));}
        }
        Set<Integer> seen=new HashSet<Integer>();heads=matches("^  \\* RecentTaskInfo #([0-9]+):[ \\t]*$",visible);
        need(!heads.isEmpty()&&visible.substring(0,heads.get(0).start()).trim().isEmpty(),"PHYSICAL_VISIBLE_RECENTS_MISSING");
        for(int i=0;i<heads.size();i++){
            Matcher h=heads.get(i);need(n(h.group(1))==i,"PHYSICAL_VISIBLE_INDICES_INCOMPLETE");
            String body=visible.substring(h.end(),i+1<heads.size()?heads.get(i+1).start():visible.length());
            Matcher identity=one("^    id=([0-9]+) userId=([0-9]+) hasTask=(true|false) lastActiveTime=[0-9]+$",body,"PHYSICAL_VISIBLE_IDENTITY_MISSING");
            int id=n(identity.group(1)),user=n(identity.group(2));Recent r=rows.get(id);need(r!=null&&seen.add(id)&&r.user==user,"PHYSICAL_VISIBLE_INTERNAL_MISMATCH");
            int display=n(one("^    lastDisplayId=(-?[0-9]+)[ \\t\\r\\n]*\\z",body,"PHYSICAL_VISIBLE_DISPLAY_MISSING").group(1));
            String excluded=one("^    isExcluded=(true|false) [^\\r\\n]*$",body,"PHYSICAL_VISIBLE_EXCLUSION_MISSING").group(1);
            String[] in=intent(one("^    baseIntent=(Intent \\{[^\\r\\n]*\\}|null)$",body,"PHYSICAL_VISIBLE_INTENT_MISSING").group(1));
            need(display==r.display&&in[0].equals(r.base)&&in[1].equals(r.flags),"PHYSICAL_VISIBLE_INTERNAL_MISMATCH");
            if(targetUser==0||user!=targetUser){String fact="visible|"+id+"|"+user+"|"+identity.group(3)+"|"+excluded+"|"+display+"|"+in[0]+"|"+in[1];
                append(out,fact);facts.add(new RecentFact(id,fact));}
        }
        Map<Integer,String> hiddenLabels=new LinkedHashMap<Integer,String>();
        if(lines.length==6){
            Matcher m=one("^mHiddenTasks=(\\[.*\\])$",lines[5],"PHYSICAL_HIDDEN_LIST_INVALID");String value=m.group(1);
            List<Matcher> hidden=matches("Task\\{[^{}\\r\\n]+\\}",value);String residual=value.replaceAll("Task\\{[^{}\\r\\n]+\\}","");
            need(residual.matches("\\[(?:, )*\\]"),"PHYSICAL_HIDDEN_LIST_INCOMPLETE");seen.clear();
            Set<String> tokens=new HashSet<String>();
            for(Matcher h:hidden){Recent item=label(h.group());Recent r=rows.get(item.task);
                need(seen.add(item.task)&&tokens.add(item.token),"PHYSICAL_HIDDEN_IDENTITY_DUPLICATE");
                if(r!=null)need(item.token.equals(r.token)&&item.affinity.equals(r.affinity),"PHYSICAL_HIDDEN_IDENTITY_MISMATCH");
                // AOSP mHiddenTasks may retain references absent from mTasks. Preserve the
                // complete observed label and sequence for every user, including unknown
                // ownership. No user, child count, task death or action authority is inferred.
                append(out,"hidden|"+h.group());facts.add(new RecentFact(item.task,"hidden|"+h.group()));
                hiddenLabels.put(item.task,h.group());
            }
        }
        return new RecentCensus(out.toString(),rows,hiddenLabels,facts,text);
    }
    public static Map<Integer,String> capture(String activities,String windows,String recents,Map<Integer,DisplayFacts> displays,int targetUser){
        need(targetUser>=0&&displays!=null&&displays.size()==2&&displays.containsKey(0)&&displays.containsKey(1)
                &&displays.get(0).id==0&&displays.get(1).id==1&&!displays.get(0).uniqueId.equals(displays.get(1).uniqueId),"PHYSICAL_DISPLAY_CENSUS_INCOMPLETE");
        Hierarchy hierarchy=activities(activities,targetUser);Map<Integer,String> focused=windows(windows,hierarchy,displays,targetUser);
        String recent=recents(recents,targetUser).projection;Map<Integer,String> result=new LinkedHashMap<Integer,String>();
        for(int id:new int[]{0,1}){StringBuilder raw=new StringBuilder();append(raw,SCHEMA);append(raw,displays.get(id).data());
            append(raw,hierarchy.rows.get(id).toString());append(raw,focused.get(id));append(raw,recent);
            result.put(id,ProfileIdentity.sha(raw.toString().getBytes(StandardCharsets.UTF_8)));}
        return Collections.unmodifiableMap(result);
    }
}
