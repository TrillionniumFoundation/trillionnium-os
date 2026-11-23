package org.trillionnium.hepta.background;

/** Pure synthetic ActivityInfo values: none of these are asserted to be Razr manifest facts. */
public final class BackgroundOwnedTaskPolicyHostTest {
    private static final String GENERATION = "3be5dca4-0edb-4131-bd9d-84e8bf73d0b7";
    private static final String PKG = "example.notes";
    private static final int FLAGS = BackgroundOwnedTaskPolicy.NEW_TASK | BackgroundOwnedTaskPolicy.MULTIPLE_TASK;
    private static int checks;

    private interface Call { void run(); }
    private static void check(boolean value, String message) {
        checks++;
        if (!value) throw new AssertionError(message);
    }
    private static void refused(Call call, String message) {
        boolean rejected = false;
        try { call.run(); } catch (IllegalArgumentException expected) { rejected = true; }
        check(rejected,message);
    }
    private static BackgroundOwnedTaskPolicy.Activity activity(int mode, int document) {
        return new BackgroundOwnedTaskPolicy.Activity(PKG,PKG+"/example.notes.Editor",10382,mode,document,
            0,true,true,true,null,null,"/product/preinstall/Example/Example.apk");
    }
    private static BackgroundOwnedTaskPolicy.Plan plan(BackgroundOwnedTaskPolicy.Activity activity, int flags) {
        return BackgroundOwnedTaskPolicy.choose(GENERATION,11,PKG,activity,flags);
    }
    private static void noProof(BackgroundOwnedTaskPolicy.Plan p) {
        check(!p.frameworkFlagsVerified && !p.taskOwnershipVerified && !p.recentsCleanupVerified,
            "outbound flag plan must never claim framework, task ownership or Recents cleanup proof");
    }
    private static void positive() {
        BackgroundOwnedTaskPolicy.Plan p = plan(activity(0,0),FLAGS);
        check(p.eligible && p.newDocumentRequested,"actual standard/NONE values allow conditional document request");
        check(p.originalFlags==FLAGS && p.outboundFlags==(FLAGS|BackgroundOwnedTaskPolicy.NEW_DOCUMENT),
            "only new-document bit is added to ordinary fresh-task flags");
        check(p.displayId==11 && p.targetUid==10382 && p.generation.equals(GENERATION)
            && p.packageName.equals(PKG) && p.component.equals(PKG+"/example.notes.Editor"),
            "plan retains the supplied live-display target identity");
        noProof(p);
        p=plan(activity(0,0),FLAGS|BackgroundOwnedTaskPolicy.RETAIN_IN_RECENTS|1|2);
        check(p.eligible && (p.outboundFlags&BackgroundOwnedTaskPolicy.RETAIN_IN_RECENTS)==0,
            "retain-in-recents is cleared only for the supported new-document case");
        check((p.outboundFlags&3)==3,"existing unrelated URI grant flags are preserved, not added or revoked");
        check((p.outboundFlags&0x00800000)==0,"policy does not add exclude-from-recents");
        noProof(p);
        p=plan(activity(0,0),FLAGS|BackgroundOwnedTaskPolicy.NEW_DOCUMENT|0x00800000);
        check(p.outboundFlags==p.originalFlags,"an existing document/exclude bit is preserved without another mutation");
        noProof(p);
    }
    private static void unsupportedModes() {
        for(int mode:new int[]{-1,1,2,3,4,99}) {
            for(int document:new int[]{-1,0,1,2,3,99}) {
                int original=FLAGS|BackgroundOwnedTaskPolicy.RETAIN_IN_RECENTS|3;
                BackgroundOwnedTaskPolicy.Plan p=plan(activity(mode,document),original);
                check(!p.eligible && p.outboundFlags==original && p.launchMode==mode
                    && p.documentLaunchMode==document,"unknown or nonstandard mode is recorded, never normalized to zero");
                noProof(p);
            }
        }
        for(int document:new int[]{-1,1,2,3,99}) {
            BackgroundOwnedTaskPolicy.Plan p=plan(activity(0,document),FLAGS);
            check(!p.eligible && p.outboundFlags==FLAGS,"INTO_EXISTING/ALWAYS/NEVER/unknown cannot claim this auto-remove condition");
            noProof(p);
        }
        for(int flags:new int[]{0,BackgroundOwnedTaskPolicy.NEW_TASK,BackgroundOwnedTaskPolicy.MULTIPLE_TASK,
                FLAGS|0x20000000,FLAGS|0x04000000,FLAGS|0x00020000,FLAGS|0x00008000}) {
            BackgroundOwnedTaskPolicy.Plan p=plan(activity(0,0),flags);
            check(!p.eligible && p.outboundFlags==flags,"in-place/reuse/clear requests retain their original flags");
            noProof(p);
        }
        BackgroundOwnedTaskPolicy.Plan already=plan(activity(2,0),FLAGS|BackgroundOwnedTaskPolicy.NEW_DOCUMENT);
        check(!already.eligible && already.newDocumentRequested && already.outboundFlags==already.originalFlags,
            "outbound bit records an existing caller request even when this policy is ineligible");
        noProof(already);
    }
    private static void identityAndChanges() {
        BackgroundOwnedTaskPolicy.Activity original=activity(0,0);
        check(original.same(activity(0,0)),"equal copied metadata matches");
        check(!original.same(null),"missing fresh metadata refuses equality");
        check(!original.same(activity(1,0)) && !original.same(activity(0,3)),"mode changes cannot pass dispatch recheck");
        for(int changed=0;changed<10;changed++) {
            BackgroundOwnedTaskPolicy.Activity next=new BackgroundOwnedTaskPolicy.Activity(
                PKG,changed==0?PKG+"/example.notes.Other":original.component,
                changed==1?10383:original.uid,0,0,changed==2?8192:0,
                changed!=3,changed!=4,changed!=5,changed==6?"example.notes.Real":null,
                changed==7?"example.permission.TEST":null,
                changed==8?"/data/app/changed/base.apk":changed==9?"/product/preinstall/Other/base.apk":original.sourceDir);
            check(!original.same(next),"component/UID/flags/enabled/alias/permission/source changes are rejected");
        }
        refused(()->BackgroundOwnedTaskPolicy.choose(null,11,PKG,original,FLAGS),"missing generation rejected");
        refused(()->BackgroundOwnedTaskPolicy.choose("wrong",11,PKG,original,FLAGS),"malformed generation rejected");
        refused(()->BackgroundOwnedTaskPolicy.choose(GENERATION,0,PKG,original,FLAGS),"main display rejected");
        refused(()->BackgroundOwnedTaskPolicy.choose(GENERATION,-1,PKG,original,FLAGS),"unknown display rejected");
        refused(()->BackgroundOwnedTaskPolicy.choose(GENERATION,11,"other.package",original,FLAGS),"different scoped package rejected");
        refused(()->BackgroundOwnedTaskPolicy.choose(GENERATION,11,PKG,null,FLAGS),"missing ActivityInfo cannot default to standard/NONE");
        refused(()->new BackgroundOwnedTaskPolicy.Activity(PKG,"other.package/.Editor",10382,0,0,0,true,true,true,null,null,"/x.apk"),"foreign component rejected");
        refused(()->new BackgroundOwnedTaskPolicy.Activity(PKG,original.component,-1,0,0,0,true,true,true,null,null,"/x.apk"),"unknown UID rejected");
        refused(()->new BackgroundOwnedTaskPolicy.Activity(PKG,original.component,110382,0,0,0,true,true,true,null,null,"/x.apk"),"different Android user rejected");
        refused(()->new BackgroundOwnedTaskPolicy.Activity(PKG,original.component,10382,0,0,0,true,true,true,null,null,null),"missing actual source path rejected");
        for(int bit=0;bit<3;bit++) {
            final int denied=bit;
            refused(()->plan(new BackgroundOwnedTaskPolicy.Activity(PKG,original.component,10382,0,0,0,
                    denied!=0,denied!=1,denied!=2,null,null,original.sourceDir),FLAGS),
                "disabled or nonexported activity cannot acquire a launch plan");
        }
    }
    public static void main(String[] args) {
        positive();unsupportedModes();identityAndChanges();
        System.out.println("BackgroundOwnedTaskPolicyHostTest checks="+checks);
    }
}
