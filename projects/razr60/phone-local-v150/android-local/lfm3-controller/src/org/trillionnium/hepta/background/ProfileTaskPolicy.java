package org.trillionnium.hepta.background;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Dedicated managed-profile admission; the user-0 and Xiaomi policies remain separate. */
public final class ProfileTaskPolicy {
    public static final int MAX_ROOTS=256, MAX_LEAVES=2048;
    private ProfileTaskPolicy() {}
    public static final class Refusal extends Exception {
        private static final long serialVersionUID=1L;
        public final String code;
        public Refusal(String code){super(code);this.code=code;}
    }
    public static void need(boolean value,String code)throws Refusal {if(!value)throw new Refusal(code);}
    /** Actual framework fields. Child users must never be copied from root.userId. */
    public static final class Root {
        public final int id,display,user,activities;
        public final boolean visible;
        public final String base,top;
        private final int[] childIds,childUsers;
        private final String[] childNames;
        private final int[][] childBounds;
        public Root(int id,int display,int user,int activities,boolean visible,String base,String top,
                    int[] ids,int[] users,String[] names,int[][] bounds)throws Refusal{
            need(id>0&&display>=0&&user>=0&&activities>=0&&activities<=MAX_LEAVES,"PROFILE_ROOT_FIELDS_INVALID");
            need(ids!=null&&users!=null&&names!=null&&bounds!=null&&ids.length==users.length
                    &&ids.length==names.length&&ids.length==bounds.length&&ids.length<=MAX_LEAVES,
                    "PROFILE_CHILD_ARRAYS_INCOMPLETE");
            need(validComponent(base)&&validComponent(top),"PROFILE_ROOT_COMPONENT_INVALID");
            this.id=id;this.display=display;this.user=user;this.activities=activities;this.visible=visible;
            this.base=base;this.top=top;childIds=ids.clone();childUsers=users.clone();childNames=names.clone();
            childBounds=new int[bounds.length][];Set<Integer> unique=new HashSet<Integer>();
            boolean empty=activities==0&&!visible&&base==null&&top==null;
            for(int i=0;i<ids.length;i++){
                need(ids[i]>0&&users[i]>=0&&unique.add(ids[i]),"PROFILE_CHILD_IDENTITY_INVALID");
                need(names[i]!=null&&(validName(names[i])||(empty&&"unknown".equals(names[i]))),
                        "PROFILE_CHILD_COMPONENT_UNKNOWN");
                int[] b=bounds[i];need(b!=null&&b.length==4&&b[2]>=b[0]&&b[3]>=b[1],"PROFILE_CHILD_BOUNDS_INVALID");
                for(int v:b)need(v>=-32768&&v<=32768,"PROFILE_CHILD_BOUNDS_INVALID");
                childBounds[i]=b.clone();
            }
        }
    }
    public static final class Leaf {
        public final int id,parent,display,user;
        public final String name;
        Leaf(Root root,int index){id=root.childIds[index];parent=root.id;display=root.display;
            user=root.childUsers[index];name=root.childNames[index];}
    }
    public static final class Snapshot {
        public final List<Root> roots;
        public final Map<Integer,Leaf> leaves;
        public final Set<Integer> allIds;
        public Snapshot(List<Root> input)throws Refusal{
            need(input!=null&&!input.isEmpty()&&input.size()<=MAX_ROOTS,"PROFILE_GLOBAL_ROOT_QUERY_INCOMPLETE");
            List<Root> copy=new ArrayList<Root>();Map<Integer,Leaf> children=new LinkedHashMap<Integer,Leaf>();
            Set<Integer> rootIds=new HashSet<Integer>(),ids=new LinkedHashSet<Integer>();
            for(Root root:input){
                need(root!=null&&rootIds.add(root.id),"PROFILE_GLOBAL_ROOT_DUPLICATE");copy.add(root);ids.add(root.id);
                for(int i=0;i<root.childIds.length;i++){
                    Leaf leaf=new Leaf(root,i);
                    need(children.put(leaf.id,leaf)==null&&children.size()<=MAX_LEAVES,"PROFILE_GLOBAL_LEAF_DUPLICATE");
                    ids.add(leaf.id);
                }
            }
            roots=Collections.unmodifiableList(copy);leaves=Collections.unmodifiableMap(children);
            allIds=Collections.unmodifiableSet(ids);
        }
        public void requireDedicatedEmpty(ProfileTarget target)throws Refusal{
            for(Root root:roots)need(root.user!=target.profile.userId,"PROFILE_ALREADY_HAS_ROOT_TASK");
            for(Leaf leaf:leaves.values())need(leaf.user!=target.profile.userId,"PROFILE_ALREADY_HAS_LEAF_TASK");
        }
        public void requireOnlyOwned(ProfileTarget target,int display,int rootId,int leafId)throws Refusal{
            int onDisplay=0;
            for(Root root:roots){
                if(root.display==display){onDisplay++;need(root.id==rootId,"PROFILE_FOREIGN_ROOT_ON_DISPLAY");}
                need(root.user!=target.profile.userId||root.id==leafId,"PROFILE_FOREIGN_TARGET_ROOT");
            }
            need(onDisplay==1,"PROFILE_OWNED_ROOT_MISSING");
            for(Leaf leaf:leaves.values()){
                if(leaf.user==target.profile.userId)
                    need(leaf.id==leafId&&leaf.parent==rootId&&leaf.display==display,"PROFILE_FOREIGN_TARGET_LEAF");
                if(leaf.display==display)
                    need((leafId>0&&leaf.id==leafId&&leaf.user==target.profile.userId&&leaf.parent==rootId)
                            ||(leafId<0&&leaf.id==rootId&&leaf.user==0),"PROFILE_FOREIGN_DISPLAY_LEAF");
            }
            if(leafId>0){Leaf leaf=leaves.get(leafId);need(leaf!=null&&leaf.user==target.profile.userId
                    &&leaf.parent==rootId&&leaf.display==display,"PROFILE_OWNED_LEAF_MISSING");}
        }
        public Map<Integer,Leaf> personalTargets(){
            Map<Integer,Leaf> result=new LinkedHashMap<Integer,Leaf>();
            for(Leaf leaf:leaves.values())if(leaf.user==0&&leaf.display==0&&inPackageName(leaf.name))result.put(leaf.id,leaf);
            for(Root root:roots)if(root.user==0&&root.display==0&&(inPackage(root.base)||inPackage(root.top)))
                for(int id:root.childIds){Leaf leaf=leaves.get(id);if(leaf.user==0)result.put(id,leaf);}
            return Collections.unmodifiableMap(result);
        }
        public Map<String,Object> personalAudit(Map<Integer,Leaf> previous){
            List<Integer> absent=new ArrayList<Integer>(),relocated=new ArrayList<Integer>(),added=new ArrayList<Integer>();
            for(Leaf old:previous.values()){
                Leaf now=leaves.get(old.id);
                if(now==null)absent.add(old.id);
                else if(now.user!=0||now.display!=0||now.parent!=old.parent)relocated.add(old.id);
            }
            Map<Integer,Leaf> current=personalTargets();
            for(int id:current.keySet())if(!previous.containsKey(id))added.add(id);
            Map<String,Object> out=new LinkedHashMap<String,Object>();
            out.put("schema","hepta.profile-personal-task-audit.v1");out.put("user_id",0);
            out.put("before_count",previous.size());out.put("current_count",current.size());
            out.put("absent_task_ids",Collections.unmodifiableList(absent));
            out.put("relocated_task_ids",Collections.unmodifiableList(relocated));
            out.put("new_task_ids",Collections.unmodifiableList(added));
            out.put("controls_profile_admission",false);out.put("repair_attempted",false);
            return Collections.unmodifiableMap(out);
        }
    }
    public static final class Recent {
        public final int id,user,uid;
        Recent(int id,int user,int uid){this.id=id;this.user=user;this.uid=uid;}
    }
    public static final class Recents {
        public final Map<Integer,Recent> rows;
        public final Set<Integer> ids;
        public final String sha256;
        public final int bytes;
        private Recents(Map<Integer,Recent> rows,BackgroundOwnedSingleTask.RecentTasks validated){
            this.rows=Collections.unmodifiableMap(rows);ids=validated.ids;sha256=validated.sha256;bytes=validated.bytes;
        }
        public static Recents parse(String text)throws Exception{
            BackgroundOwnedSingleTask.RecentTasks checked=BackgroundOwnedSingleTask.RecentTasks.parse(text);
            Map<Integer,Recent> rows=new LinkedHashMap<Integer,Recent>();int current=-1;boolean raw=false;
            Pattern header=Pattern.compile("  \\* Recent #[0-9]+: Task\\{[^\\s{}]+ #([0-9]+) .+\\}");
            Pattern identity=Pattern.compile("    userId=(0|[1-9][0-9]*) effectiveUid=([^\\s]+)(?: (.*))?");
            Pattern duplicateIdentity=Pattern.compile("(?:^|\\s)(?:userId|effectiveUid)=");
            for(String line:text.split("\\n",-1)){
                if("  Recent tasks:".equals(line)){raw=true;continue;}
                if("  Visible recent tasks (most recent first):".equals(line))break;
                if(!raw)continue;
                Matcher h=header.matcher(line);
                if(h.matches()){current=parseInt(h.group(1));continue;}
                if(line.startsWith("    userId=")){
                    Matcher m=identity.matcher(line);need(current>0&&m.matches(),"PROFILE_RECENT_USER_UNKNOWN");
                    need(m.group(3)==null||!duplicateIdentity.matcher(m.group(3)).find(),
                            "PROFILE_RECENT_IDENTITY_DUPLICATE");
                    int user=parseInt(m.group(1)),uid=recentUid(m.group(2));
                    need(uid/100000==user,"PROFILE_RECENT_UID_USER_MISMATCH");
                    need(rows.put(current,new Recent(current,user,uid))==null,"PROFILE_RECENT_IDENTITY_DUPLICATE");
                }
            }
            need(rows.keySet().equals(checked.ids),"PROFILE_RECENT_IDENTITY_INCOMPLETE");
            return new Recents(rows,checked);
        }
        // Android 16 QPR2 UserHandle.formatUid(PrintWriter,int), not a package UID guess.
        // Keep the pre-existing decimal UID input; formatted forms must be canonical.
        private static int recentUid(String text)throws Refusal{
            if(text.matches("0|[1-9][0-9]*"))return parseInt(text);
            Matcher m=Pattern.compile("u(0|[1-9][0-9]*)(ai|a|i|s)(0|[1-9][0-9]*)").matcher(text);
            need(m.matches(),"PROFILE_RECENT_UID_INVALID");
            int user=parseInt(m.group(1)),offset=parseInt(m.group(3));
            String kind=m.group(2);long appId;
            if("a".equals(kind)){
                need(offset<=79999,"PROFILE_RECENT_UID_INVALID");appId=10000L+offset;
            }else if("s".equals(kind)){
                need(user>0&&offset<=9999,"PROFILE_RECENT_UID_INVALID");appId=offset;
            }else if("ai".equals(kind)){
                // The producer uses ai at exactly FIRST_ISOLATED_UID (99000) too.
                need(offset<=9000,"PROFILE_RECENT_UID_INVALID");appId=90000L+offset;
            }else{
                need(offset>=1&&offset<=999,"PROFILE_RECENT_UID_INVALID");appId=99000L+offset;
            }
            long uid=(long)user*100000L+appId;
            need(uid>=10000L&&uid<=Integer.MAX_VALUE,"PROFILE_RECENT_UID_INVALID");
            return (int)uid;
        }
        public void requireDedicatedEmpty(ProfileTarget target)throws Refusal{
            for(Recent row:rows.values())need(row.user!=target.profile.userId,"PROFILE_ALREADY_HAS_RECENT_TASK");
        }
        public void requireOnlyOwned(ProfileTarget target,int leafId)throws Refusal{
            for(Recent row:rows.values())if(row.user==target.profile.userId)
                need(row.id==leafId&&row.uid==target.fullUid,"PROFILE_FOREIGN_RECENT_TASK");
        }
    }
    /** Actual PM fields, captured independently of the expected target identity. */
    public static final class Activity {
        public final String packageName,component,sourceDir,affinity,targetActivity,permission;
        public final int uid,launchMode,documentMode,flags,forbiddenMask;
        public final boolean enabled,applicationEnabled,exported;
        public Activity(String pkg,String component,int uid,int launchMode,int documentMode,int flags,
                int forbiddenMask,boolean enabled,boolean appEnabled,boolean exported,String targetActivity,
                String permission,String sourceDir,String affinity){
            packageName=pkg;this.component=component;this.uid=uid;this.launchMode=launchMode;
            this.documentMode=documentMode;this.flags=flags;this.forbiddenMask=forbiddenMask;
            this.enabled=enabled;applicationEnabled=appEnabled;this.exported=exported;
            this.targetActivity=targetActivity;this.permission=permission;this.sourceDir=sourceDir;this.affinity=affinity;
        }
        public void requireEligible(ProfileTarget target)throws Refusal{
            need(target!=null&&target.packageName.equals(packageName)&&target.component.equals(component)
                    &&uid==target.fullUid&&uid/100000==target.profile.userId,"PROFILE_LAUNCH_IDENTITY_MISMATCH");
            need(enabled&&applicationEnabled&&exported&&targetActivity==null&&(permission==null||permission.isEmpty())
                    &&sourceDir!=null&&sourceDir.startsWith("/")&&forbiddenMask!=0&&(flags&forbiddenMask)==0
                    &&documentMode==0&&(launchMode==0||launchMode==2),"PROFILE_LAUNCH_CAPABILITY_UNAVAILABLE");
        }
        public boolean same(Activity a){return a!=null&&uid==a.uid&&launchMode==a.launchMode&&documentMode==a.documentMode
                &&flags==a.flags&&forbiddenMask==a.forbiddenMask&&enabled==a.enabled&&applicationEnabled==a.applicationEnabled
                &&exported==a.exported&&Objects.equals(packageName,a.packageName)&&Objects.equals(component,a.component)
                &&Objects.equals(sourceDir,a.sourceDir)&&Objects.equals(affinity,a.affinity)
                &&Objects.equals(targetActivity,a.targetActivity)&&Objects.equals(permission,a.permission);}
    }
    private static int parseInt(String value)throws Refusal{
        try{return Integer.parseInt(value);}catch(NumberFormatException invalid){throw new Refusal("PROFILE_INTEGER_INVALID");}
    }
    private static boolean validComponent(String s){return s==null||s.matches("[A-Za-z][A-Za-z0-9_.]*/[A-Za-z_.$][A-Za-z0-9_.$]*");}
    private static boolean validName(String s){return (validComponent(s)&&s!=null)||BrokerProtocol.packageName(s);}
    private static boolean inPackageName(String s){return ProfileTarget.CTRIP.equals(s)||inPackage(s);}
    private static boolean inPackage(String s){return s!=null&&s.startsWith(ProfileTarget.CTRIP+"/");}
}
