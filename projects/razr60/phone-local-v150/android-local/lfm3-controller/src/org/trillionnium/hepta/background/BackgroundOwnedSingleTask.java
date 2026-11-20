package org.trillionnium.hepta.background;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
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

/**
 * A bounded owner of two newly-created organizer containers and one normal app leaf.
 * The Android adapter supplies real TaskInfo/token/cookie observations. Host doubles do not
 * establish Android capability. The original standard/document policy is a separate path.
 */
public final class BackgroundOwnedSingleTask {
    public static final String PACKAGE = "com.xiaomi.shop";
    public static final String COMPONENT = PACKAGE + "/com.xiaomi.shop2.activity.MainActivity";
    public static final String ACTION = "com.xiaomi.shop.action_show_home";
    public static final String SCHEMA = "hepta.background-owned-single-task.v1";
    private static final int FLAGS = BackgroundOwnedTaskPolicy.NEW_TASK | BackgroundOwnedTaskPolicy.MULTIPLE_TASK;
    private static final int FORBIDDEN_MANIFEST_FLAGS = 0x0040 | 0x1000;
    public static final int MAX_DUMP_BYTES = 1024 * 1024;

    public interface Platform {
        Object newCookie();
        void guard() throws Exception;
        List<Task> roots() throws Exception;
        List<Task> children(Object token) throws Exception;
        Set<Integer> liveTaskIds() throws Exception;
        Set<Integer> liveLeafTaskIds() throws Exception;
        String activitiesDump() throws Exception;
        String recentsDump() throws Exception;
        void createRoot(Object cookie) throws Exception;
        void reparentEmpty(Object childToken, Object parentToken) throws Exception;
        void bindLaunch(Object rootToken, int rootId, Object launchCookie) throws Exception;
        void removeOwnedLeaf(Object token) throws Exception;
        boolean deleteOwnedContainer(Object token) throws Exception;
    }

    /** Fields copied from the framework object, never filled from current PackageManager metadata. */
    public static final class Task {
        public final int id, display, user, parent, uid, topUid, activities;
        public final Object token;
        public final List<Object> cookies;
        public final String intentComponent, base, top, real, orig;
        public final boolean running, visible;
        public Task(int id, int display, int user, int parent, int uid, int topUid, int activities,
                    Object token, List<Object> cookies, String intentComponent, String base,
                    String top, String real, String orig, boolean running, boolean visible) {
            this.id=id; this.display=display; this.user=user; this.parent=parent; this.uid=uid;
            this.topUid=topUid; this.activities=activities; this.token=token;
            this.cookies=Collections.unmodifiableList(new ArrayList<Object>(cookies));
            this.intentComponent=intentComponent; this.base=base; this.top=top; this.real=real;
            this.orig=orig; this.running=running; this.visible=visible;
        }
        boolean cookie(Object expected) { return cookies.contains(expected); }
    }

    public static final class Refusal extends Exception {
        private static final long serialVersionUID=1L;
        public final String code;
        Refusal(String code) { super(code); this.code=code; }
    }

    public static boolean eligible(BackgroundOwnedTaskPolicy.Activity a, int flags) {
        return a != null && PACKAGE.equals(a.packageName) && COMPONENT.equals(a.component)
            && a.uid >= 10000 && a.uid < 100000 && a.launchMode == 2 && a.documentLaunchMode == 0
            && a.enabled && a.applicationEnabled && a.exported && a.targetActivity == null
            && (a.permission == null || a.permission.length() == 0)
            && (a.manifestFlags & FORBIDDEN_MANIFEST_FLAGS) == 0 && flags == FLAGS;
    }

    private final Platform platform;
    private final String generation, requestId;
    private final int display, uid;
    private final Object rootCookie, anchorCookie, launchCookie;
    private final Set<Integer> beforeIds = new LinkedHashSet<Integer>();
    private Task root, anchor, leaf;
    private boolean rootCreateAttempted, anchorCreateAttempted, prepared, dispatchMarked;
    private boolean frameworkAccepted, ownershipVerified, removalAttempted, leafRemovalRequested;
    private boolean anchorRemovalRequested, rootRemovalRequested, cleanupVerified, identityUnknown;
    private String activitiesSha, recentsBeforeSha, recentsAfterSha;
    private int activitiesBytes, recentsBeforeBytes, recentsAfterBytes, recentsBeforeCount;

    public BackgroundOwnedSingleTask(Platform platform, String generation, String requestId,
                                    int display, BackgroundOwnedTaskPolicy.Activity activity, int flags)
            throws Refusal {
        String uuid="[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
        need(platform != null && generation != null && generation.matches(uuid)
            && requestId != null && requestId.matches(uuid) && display > 0
            && eligible(activity, flags), "OWNED_TASK_ACTIVITY_NOT_ELIGIBLE");
        this.platform=platform; this.generation=generation; this.requestId=requestId;
        this.display=display; this.uid=activity.uid;
        rootCookie=platform.newCookie(); anchorCookie=platform.newCookie(); launchCookie=platform.newCookie();
        need(rootCookie != null && anchorCookie != null && launchCookie != null
            && rootCookie != anchorCookie && rootCookie != launchCookie && anchorCookie != launchCookie,
            "OWNED_TASK_COOKIE_INVALID");
    }

    public void prepare() throws Exception {
        need(!rootCreateAttempted && !prepared, "OWNED_TASK_CREATE_ALREADY_ATTEMPTED");
        platform.guard();
        String activities=platform.activitiesDump();
        validateDump(activities, "ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)");
        need(Pattern.compile("^  TaskOrganizerController:$",Pattern.MULTILINE).matcher(activities).find()
            && Pattern.compile("^  SleepTokens=.+$",Pattern.MULTILINE).matcher(activities).find(),
            "ACTIVITIES_DUMP_TAIL_INCOMPLETE");
        RecentTasks recents=RecentTasks.parse(platform.recentsDump());
        need(!packageMentioned(activities) && !packageMentioned(recents.text), "APP_ALREADY_HAS_TASK");
        activitiesSha=sha(activities); activitiesBytes=bytes(activities);
        recentsBeforeSha=recents.sha256; recentsBeforeBytes=recents.bytes; recentsBeforeCount=recents.ids.size();
        beforeIds.addAll(platform.liveTaskIds()); beforeIds.addAll(recents.ids);
        need(checked(platform.roots()).isEmpty(), "OWNED_DISPLAY_NOT_EMPTY");
        platform.guard();
        rootCreateAttempted=true;
        platform.createRoot(rootCookie);
        root=createdRoot(rootCookie, checked(platform.roots()), 1);
        need(checked(platform.children(root.token)).isEmpty(), "OWNED_ROOT_NOT_LEAF_EMPTY");
        platform.guard();
        anchorCreateAttempted=true;
        platform.createRoot(anchorCookie);
        List<Task> roots=checked(platform.roots());
        sameRoot(findToken(roots, root.token), false);
        anchor=createdRoot(anchorCookie, roots, 2);
        need(anchor.id != root.id && !Objects.equals(anchor.token, root.token), "OWNED_CONTAINER_COLLISION");
        need(checked(platform.children(anchor.token)).isEmpty(), "OWNED_ANCHOR_NOT_LEAF_EMPTY");
        platform.guard();
        // Only these two new, cookie-bound empty tokens are ever reparented.
        platform.reparentEmpty(anchor.token, root.token);
        verifyPrepared();
        platform.bindLaunch(root.token, root.id, launchCookie);
        prepared=true;
    }

    /** The caller rechecks PM and the original display/main-screen guard before this final read. */
    public void beforeDispatch() throws Exception {
        need(prepared && !dispatchMarked, "OWNED_TASK_DISPATCH_ALREADY_ATTEMPTED");
        platform.guard(); verifyPrepared(); platform.guard();
        dispatchMarked=true;
    }

    public void accepted(int result) throws Refusal {
        need(dispatchMarked && !frameworkAccepted && result == 0, "OWNED_TASK_START_NOT_FRESH_SUCCESS");
        frameworkAccepted=true;
    }

    public boolean observe() throws Exception {
        need(frameworkAccepted && !removalAttempted, "OWNED_TASK_START_NOT_ACCEPTED");
        // The broker checks the current request. Do not reuse the already-finished launch deadline.
        List<Task> roots=checked(platform.roots());
        need(roots.size() == 1, "OWNED_DISPLAY_ROOT_CHANGED");
        Task currentRoot=findToken(roots, root.token); sameRoot(currentRoot, true);
        List<Task> children=checked(platform.children(root.token));
        Task currentAnchor=findToken(children, anchor.token); sameAnchor(currentAnchor);
        if (children.size() == 1) return false;
        need(children.size() == 2, "OWNED_TASK_CHILDREN_CHANGED");
        Task candidate=children.get(0).token.equals(anchor.token) ? children.get(1) : children.get(0);
        requireLeaf(candidate);
        if (leaf != null) need(sameIdentity(leaf,candidate), "OWNED_LEAF_IDENTITY_CHANGED");
        leaf=candidate;
        if (!candidate.visible || !candidate.running || candidate.activities < 1) return false;
        ownershipVerified=true;
        return true;
    }

    /** A literal unknown name is allowed only for this still-empty, independently re-read anchor. */
    boolean provesEmptyAnchor(int observedDisplay,int observedRootId,int observedChildId) throws Exception {
        if(!frameworkAccepted || root==null || anchor==null || observedDisplay!=display
            || observedRootId!=root.id || observedChildId!=anchor.id) return false;
        // No activeCheck/locationCheck/guard callback: snapshot itself calls this method.
        List<Task> roots=checked(platform.roots());
        need(roots.size()==1,"OWNED_DISPLAY_ROOT_CHANGED");
        sameRoot(findToken(roots,root.token),true);
        List<Task> children=checked(platform.children(root.token));
        need(children.size()>=1 && children.size()<=2,"OWNED_TASK_CHILDREN_CHANGED");
        sameAnchor(findToken(children,anchor.token));
        Set<Integer> leaves=platform.liveLeafTaskIds();
        need(leaves.contains(anchor.id) && !leaves.contains(root.id),"OWNED_ROOT_NOT_NONLEAF");
        return true;
    }

    /** Called by the normal close path; every removal uses a retained framework token. */
    public void retire() throws Exception {
        need(!removalAttempted, "OWNED_TASK_REMOVAL_ALREADY_ATTEMPTED");
        removalAttempted=true;
        try {
            // A failed/ambiguous create is not repaired by deleting arbitrary tasks.
            need(!rootCreateAttempted || root != null, "OWNED_ROOT_CREATE_UNRESOLVED");
            need(!anchorCreateAttempted || anchor != null, "OWNED_ANCHOR_CREATE_UNRESOLVED");
            if (root == null) return;
            List<Task> roots=checked(platform.roots());
            Task currentRoot=findToken(roots, root.token); sameRoot(currentRoot, dispatchMarked);
            List<Task> children=checked(platform.children(root.token));
            if (anchor != null) {
                Task currentAnchor=findToken(children, anchor.token);
                if (currentAnchor == null) {
                    // Only the pre-reparent failure state may have the anchor still as its own root.
                    need(!prepared && !dispatchMarked, "OWNED_ANCHOR_MISSING");
                    currentAnchor=findToken(roots, anchor.token); empty(currentAnchor, -1, anchorCookie);
                } else sameAnchor(currentAnchor);
                for (Task child:children) {
                    if (Objects.equals(child.token,anchor.token)) continue;
                    need(dispatchMarked && frameworkAccepted, "OWNED_UNEXPECTED_APP_CHILD");
                    requireLeaf(child);
                    if (leaf != null) need(sameIdentity(leaf,child), "OWNED_LEAF_IDENTITY_CHANGED");
                    leaf=child;
                }
                need(children.size() <= (dispatchMarked ? 2 : 1), "OWNED_UNEXPECTED_CHILDREN");
            } else need(children.isEmpty(), "OWNED_UNEXPECTED_CHILDREN");
            // The original root guard still vetoes a target task on another display.
            // On close the adapter uses this location check without renewing an expired request.
            if (leaf != null) {
                need(findToken(children,leaf.token) != null, "OWNED_LEAF_NO_LONGER_ATTACHED");
                requireLeaf(findToken(children,leaf.token));
                platform.removeOwnedLeaf(leaf.token);
                leafRemovalRequested=true;
            }
            if (anchor != null) {
                need(platform.deleteOwnedContainer(anchor.token), "OWNED_ANCHOR_DELETE_NOT_ACCEPTED");
                anchorRemovalRequested=true;
            }
            need(platform.deleteOwnedContainer(root.token), "OWNED_ROOT_DELETE_NOT_ACCEPTED");
            rootRemovalRequested=true;
        } catch (Exception e) { identityUnknown=true; throw e; }
    }

    /** Actual complete live-ID and unfiltered raw-recents readback, after the removal requests. */
    public boolean absent() throws Exception {
        if (identityUnknown || !removalAttempted) return false;
        if (rootCreateAttempted && (!rootRemovalRequested || root == null)) return false;
        if (anchorCreateAttempted && (!anchorRemovalRequested || anchor == null)) return false;
        if (leaf != null && !leafRemovalRequested) return false;
        Set<Integer> live=platform.liveTaskIds();
        RecentTasks recents=RecentTasks.parse(platform.recentsDump());
        recentsAfterSha=recents.sha256; recentsAfterBytes=recents.bytes;
        for (Task t:new Task[]{root,anchor,leaf}) if (t != null && (live.contains(t.id)||recents.ids.contains(t.id))) return false;
        cleanupVerified=true;
        return true;
    }

    private void verifyPrepared() throws Exception {
        List<Task> roots=checked(platform.roots());
        need(roots.size()==1, "OWNED_DISPLAY_ROOT_CHANGED");
        sameRoot(findToken(roots,root.token),false);
        List<Task> children=checked(platform.children(root.token));
        need(children.size()==1, "OWNED_ANCHOR_NOT_UNIQUE");
        sameAnchor(children.get(0));
        Set<Integer> leaves=platform.liveLeafTaskIds();
        need(leaves.contains(anchor.id) && !leaves.contains(root.id), "OWNED_ROOT_NOT_NONLEAF");
    }

    private Task createdRoot(Object cookie, List<Task> roots, int count) throws Exception {
        need(roots.size()==count, "OWNED_CREATE_ROOT_COUNT");
        Task found=null;
        for (Task t:roots) if(t.cookie(cookie)) { need(found==null,"OWNED_COOKIE_NOT_UNIQUE"); found=t; }
        empty(found,-1,cookie);
        need(!beforeIds.contains(found.id), "OWNED_CREATED_ID_PREEXISTED");
        need(platform.liveLeafTaskIds().contains(found.id), "OWNED_CREATED_ROOT_NOT_LEAF");
        return found;
    }

    private void sameRoot(Task current, boolean mayHaveActivity) throws Refusal {
        need(current!=null && sameIdentity(root,current) && current.parent==-1 && current.cookie(rootCookie),
            "OWNED_ROOT_IDENTITY_CHANGED");
        need(current.uid==root.uid && current.intentComponent==null && current.real==null && current.orig==null,
            "OWNED_CONTAINER_TASK_IDENTITY_CHANGED");
        if(!mayHaveActivity) need(current.activities==0 && !current.running && current.base==null && current.top==null,
            "OWNED_ROOT_NOT_EMPTY");
    }

    private void sameAnchor(Task current) throws Refusal {
        need(current!=null && sameIdentity(anchor,current) && current.uid==anchor.uid, "OWNED_ANCHOR_IDENTITY_CHANGED");
        empty(current,root.id,anchorCookie);
    }

    private void empty(Task t,int parent,Object cookie) throws Refusal {
        need(t!=null && t.id>0 && t.token!=null && t.display==display && t.user==0 && t.parent==parent
            && t.activities==0 && !t.running && !t.visible && t.intentComponent==null && t.base==null
            && t.top==null && t.real==null && t.orig==null && t.topUid==-1 && t.cookie(cookie),
            "OWNED_CONTAINER_NOT_PROVEN_EMPTY");
    }

    private void requireLeaf(Task t) throws Exception {
        need(t!=null && t.id>0 && t.token!=null && t.display==display && t.user==0 && t.parent==root.id
            && t.uid==uid && t.topUid==uid && t.cookie(launchCookie) && !beforeIds.contains(t.id)
            && t.id!=root.id && t.id!=anchor.id && !Objects.equals(t.token,root.token)
            && !Objects.equals(t.token,anchor.token) && COMPONENT.equals(t.intentComponent)
            && COMPONENT.equals(t.real) && t.orig==null && inPackage(t.base) && inPackage(t.top),
            "OWNED_NEW_LEAF_IDENTITY_NOT_PROVEN");
        need(platform.liveLeafTaskIds().contains(t.id), "OWNED_APP_TASK_NOT_LEAF");
    }

    private boolean sameIdentity(Task a,Task b) {
        return a!=null && b!=null && a.id==b.id && a.display==b.display && a.user==b.user
            && Objects.equals(a.token,b.token);
    }
    private static boolean inPackage(String component) {return component!=null && component.startsWith(PACKAGE+"/");}
    private static Task findToken(List<Task> rows,Object token) throws Refusal {
        Task found=null;
        for(Task t:rows)if(Objects.equals(t.token,token)){need(found==null,"OWNED_DUPLICATE_TOKEN");found=t;}
        return found;
    }
    private static List<Task> checked(List<Task> rows) throws Refusal {
        need(rows!=null && rows.size()<=2048,"OWNED_TASK_QUERY_INCOMPLETE");
        Set<Integer> ids=new HashSet<Integer>(); Set<Object> tokens=new HashSet<Object>();
        for(Task t:rows)need(t!=null && t.id>0 && t.token!=null && t.activities>=0 && t.activities<=2048
            && ids.add(t.id) && tokens.add(t.token),"OWNED_TASK_QUERY_INVALID");
        return rows;
    }
    private static void need(boolean value,String code) throws Refusal {if(!value)throw new Refusal(code);}

    static boolean packageMentioned(String text) {
        String p=Pattern.quote(PACKAGE);
        return Pattern.compile("(?:ActivityRecord\\{[^\\n]*\\bu[0-9]+\\s+|(?:mActivityComponent|realActivity|origActivity|cmp|baseActivity|topActivity)=)"+p+"/").matcher(text).find()
            || Pattern.compile("(?:^|[\\s{])(?:affinity=|rootAffinity=|A=)[0-9]+:"+p+"(?=[\\s}]|$)",Pattern.MULTILINE).matcher(text).find()
            || Pattern.compile("(?:^|\\s)mCallingPackage="+p+"(?=\\s|$)",Pattern.MULTILINE).matcher(text).find();
    }

    public static final class RecentTasks {
        public final String text,sha256;
        public final int bytes;
        public final Set<Integer> ids;
        private RecentTasks(String text,Set<Integer> ids) throws Exception {
            this.text=text;this.sha256=sha(text);this.bytes=bytes(text);
            this.ids=Collections.unmodifiableSet(ids);
        }
        public static RecentTasks parse(String text) throws Exception {
            validateDump(text,"ACTIVITY MANAGER RECENT TASKS (dumpsys activity recents)");
            String[] lines=text.split("\\n",-1);
            need(lines.length>=5 && lines[1].startsWith("mRecentsUid=")
                && lines[2].startsWith("mRecentsComponent=")
                && lines[3].startsWith("mFreezeTaskListReordering=")
                && lines[4].startsWith("mFreezeTaskListReorderingPendingTimeout="),"RECENTS_HEADER_INCOMPLETE");
            int raw=-1,visible=lines.length;
            for(int i=5;i<lines.length;i++) {
                if("  Recent tasks:".equals(lines[i])) {need(raw<0,"RECENTS_DUPLICATE_HEADER");raw=i;}
                if("  Visible recent tasks (most recent first):".equals(lines[i])) {need(visible==lines.length,"RECENTS_DUPLICATE_VISIBLE_HEADER");visible=i;}
            }
            LinkedHashSet<Integer> ids=new LinkedHashSet<Integer>();
            if(raw<0) {
                for(int i=5;i<lines.length;i++)need(lines[i].isEmpty()||lines[i].startsWith("mHiddenTasks="),"RECENTS_MISSING_RAW_SECTION");
                return new RecentTasks(text,ids);
            }
            need(raw<visible,"RECENTS_SECTION_ORDER");
            Pattern start=Pattern.compile("  \\* Recent #([0-9]+): Task\\{[^\\s{}]+ #([0-9]+) .+\\}");
            int ordinal=0,current=-1;boolean identity=false,taskId=false,activities=false;
            for(int i=raw+1;i<visible;i++) {
                String line=lines[i];Matcher match=start.matcher(line);
                if(match.matches()) {
                    if(current>=0)need(identity&&taskId&&activities,"RECENTS_TASK_DETAIL_INCOMPLETE");
                    need(Integer.parseInt(match.group(1))==ordinal++,"RECENTS_NONCONTIGUOUS_ORDINAL");
                    current=Integer.parseInt(match.group(2));need(current>0&&ids.add(current)&&ids.size()<=2048,"RECENTS_TASK_ID_INVALID");
                    identity=false;taskId=false;activities=false;
                } else {
                    need(!line.startsWith("  * Recent")&&(current>=0||line.isEmpty()),"RECENTS_TASK_HEADER_INVALID");
                    if(line.startsWith("    userId=")) {need(!identity&&line.contains(" effectiveUid="),"RECENTS_UID_DETAIL_INVALID");identity=true;}
                    if(line.startsWith("    taskId=")) {need(!taskId&&line.matches("    taskId="+current+" rootTaskId=[0-9]+"),"RECENTS_ID_DETAIL_INVALID");taskId=true;}
                    if(line.startsWith("    Activities=")) {need(!activities&&line.startsWith("    Activities=[")&&line.endsWith("]"),"RECENTS_ACTIVITIES_DETAIL_INVALID");activities=true;}
                }
            }
            need(current>=0&&identity&&taskId&&activities,"RECENTS_TASK_DETAIL_INCOMPLETE");
            return new RecentTasks(text,ids);
        }
    }

    private static void validateDump(String text,String header) throws Refusal {
        need(text!=null&&bytes(text)>0&&bytes(text)<=MAX_DUMP_BYTES&&!text.contains("\0")
            &&text.startsWith(header+"\n")&&text.indexOf(header,header.length())<0,
            "TASK_DUMP_INCOMPLETE");
    }
    private static int bytes(String s){return s.getBytes(StandardCharsets.UTF_8).length;}
    private static String sha(String s) throws Exception {
        byte[] digest=MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
        StringBuilder out=new StringBuilder();for(byte b:digest)out.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return out.toString();
    }

    public Map<String,Object> evidence() {
        LinkedHashMap<String,Object> out=new LinkedHashMap<String,Object>();
        out.put("schema",SCHEMA);out.put("generation",generation);out.put("request_id",requestId);
        out.put("display_id",display);out.put("package",PACKAGE);out.put("component",COMPONENT);out.put("target_uid",uid);
        out.put("original_standard_policy_unchanged",true);out.put("explicit_nonleaf_launch_task_id_configured",prepared);
        out.put("global_single_task_find_bypass_is_aosp_source_contract",true);
        out.put("prepared",prepared);out.put("dispatch_marked",dispatchMarked);out.put("framework_start_success",frameworkAccepted);
        out.put("new_leaf_ownership_verified",ownershipVerified);out.put("identity_unknown",identityUnknown);
        out.put("root",taskEvidence(root));out.put("anchor",taskEvidence(anchor));out.put("leaf",taskEvidence(leaf));
        out.put("activities_before_bytes",activitiesBytes);out.put("activities_before_sha256",activitiesSha);
        out.put("recents_before_bytes",recentsBeforeBytes);out.put("recents_before_sha256",recentsBeforeSha);out.put("recents_before_count",recentsBeforeCount);
        out.put("recents_after_bytes",recentsAfterBytes);out.put("recents_after_sha256",recentsAfterSha);
        out.put("leaf_removal_requested",leafRemovalRequested);out.put("leaf_removal_platform_kill_process_argument",true);
        out.put("anchor_removal_requested",anchorRemovalRequested);out.put("root_removal_requested",rootRemovalRequested);
        out.put("owned_live_and_recents_absence_verified",cleanupVerified);out.put("arbitrary_task_id_removal_used",false);
        out.put("force_stop_used",false);out.put("global_task_organizer_registered",false);
        return Collections.unmodifiableMap(out);
    }
    private Map<String,Object> taskEvidence(Task t) {
        if(t==null)return null;LinkedHashMap<String,Object> out=new LinkedHashMap<String,Object>();
        out.put("task_id",t.id);out.put("display_id",t.display);out.put("user_id",t.user);out.put("parent_task_id",t.parent);
        out.put("effective_uid",t.uid);out.put("top_activity_uid",t.topUid);out.put("num_activities",t.activities);
        out.put("base_intent_component",t.intentComponent);out.put("base_activity",t.base);out.put("top_activity",t.top);
        out.put("real_activity",t.real);out.put("orig_activity",t.orig);out.put("token_identity_in_this_process",System.identityHashCode(t.token));
        out.put("token_identity_is_not_serialized_authority",true);return out;
    }
}
