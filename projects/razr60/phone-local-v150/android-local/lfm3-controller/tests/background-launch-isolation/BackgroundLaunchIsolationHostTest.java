package org.trillionnium.hepta.background;
/** Host inputs are synthetic, not claims about the installed Motorola manifests. */
public final class BackgroundLaunchIsolationHostTest {
    private static int checks,rejected,admitted;
    private static final int FLAGS=BackgroundOwnedTaskPolicy.NEW_TASK|BackgroundOwnedTaskPolicy.MULTIPLE_TASK;
    private static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
    private static BackgroundOwnedTaskPolicy.Activity activity(int mode,int document){
        return new BackgroundOwnedTaskPolicy.Activity("test.b","test.b/.Middle",10032,mode,document,0,true,true,true,null,null,"/data/app/test.b/base.apk");
    }
    private static void rejected(int mode,int document,int flags)throws Exception {
        BrokerLaunchAdmissionFixture broker=new BrokerLaunchAdmissionFixture();
        broker.demonstrateMetadataGap(); // Metadata absence is not the authorization.
        boolean refused=false;
        try{broker.launch(activity(mode,document),flags);}
        catch(BrokerProtocol.Refusal error){refused="BACKGROUND_LAUNCH_CAPABILITY_UNAVAILABLE".equals(error.code);}
        check(refused,"unsupported launch must return a stable capability refusal");
        check(broker.launches==0&&broker.flagMutations==0,"reject before outbound Intent mutation or launch");
        BackgroundOwnedTaskPolicy.Plan receipt=broker.taskLaunchPolicies.get("request");
        check(receipt!=null&&!receipt.eligible,"record why plan is unsupported without claiming dispatch");
        check(!receipt.frameworkFlagsVerified&&!receipt.taskOwnershipVerified&&!receipt.recentsCleanupVerified,"do not invent task ownership or cleanup");
        rejected++;
    }
    private static void admitted(int flags)throws Exception {
        BrokerLaunchAdmissionFixture broker=new BrokerLaunchAdmissionFixture();
        broker.launch(activity(0,0),flags);
        check(broker.launches==1&&broker.flagMutations==1,"supported fresh task reaches one launch");
        BackgroundOwnedTaskPolicy.Plan receipt=broker.taskLaunchPolicies.get("request");
        check(receipt!=null&&receipt.eligible&&receipt.newDocumentRequested,"retain standard/NONE new task policy");
        check((receipt.outboundFlags&FLAGS)==FLAGS,"keep both fresh-task flags");
        check(!receipt.taskOwnershipVerified&&!receipt.frameworkFlagsVerified,"launch request is not a framework isolation proof");
        admitted++;
    }
    public static void main(String[] args)throws Exception {
        for(int flags:new int[]{FLAGS,FLAGS|BackgroundOwnedTaskPolicy.RETAIN_IN_RECENTS,FLAGS|BackgroundOwnedTaskPolicy.NEW_DOCUMENT,FLAGS|3})admitted(flags);
        for(int mode:new int[]{-1,1,2,3,4,99})for(int document:new int[]{-1,0,1,2,3,99})rejected(mode,document,FLAGS);
        for(int document:new int[]{-1,1,2,3,99})rejected(0,document,FLAGS);
        for(int flags:new int[]{0,BackgroundOwnedTaskPolicy.NEW_TASK,BackgroundOwnedTaskPolicy.MULTIPLE_TASK,FLAGS|0x20000000,FLAGS|0x04000000,FLAGS|0x00020000,FLAGS|0x00008000})rejected(0,0,flags);
        System.out.println("BackgroundLaunchIsolationHostTest checks="+checks+" admitted="+admitted+" rejected="+rejected+" metadata_gap_reproduced=true phone_launches=0");
    }
}
