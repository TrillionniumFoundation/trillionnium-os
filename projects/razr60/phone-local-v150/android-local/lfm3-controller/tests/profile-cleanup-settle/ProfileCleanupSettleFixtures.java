package org.trillionnium.hepta.background;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.*;
import java.util.function.LongSupplier;
import java.util.regex.*;

/** Synthetic framework/clock ports. The measured 277 deadline/history offsets
 * constrain the timing projection, not an invented archived Binder census. */
final class ProfileCleanupSettleFixtures {
    static String before;
    static final ProfileTarget TARGET=ProfileBrokerHostTest.target(10,1010367);
    static void load(String path)throws Exception{before=new String(Files.readAllBytes(Paths.get(path)),StandardCharsets.UTF_8);}
    static String leafRecent(String raw){
        String row="  * Recent #0: Task{aabb300 #300 type=standard A=1010367:ctrip.android.view}\n"
            +"    userId=10 effectiveUid=u10a367 mCallingUid=0\n    affinity=1010367:ctrip.android.view\n"
            +"    intent={flg=0x10000000 cmp="+ProfileBrokerHostTest.SPLASH+"}\n"
            +"    mActivityComponent="+ProfileBrokerHostTest.HOME+"\n"
            +"    Activities=[ActivityRecord{aabb u10 "+ProfileBrokerHostTest.HOME+" t300}]\n"
            +"    taskId=300 rootTaskId=200\n    lastActiveTime=355000000 (inactive for 0s)\n    lastDisplayId=7\n";
        if(raw.indexOf("  Recent tasks:\n")<0)throw new AssertionError("complete synthetic history header");
        Matcher m=Pattern.compile("(?m)^  \\* Recent #[0-9]+:").matcher(raw.replace("  Recent tasks:\n","  Recent tasks:\n"+row));
        StringBuffer out=new StringBuffer();int n=0;
        while(m.find())m.appendReplacement(out,Matcher.quoteReplacement("  * Recent #"+n+++":"));
        m.appendTail(out);return out.toString();
    }
    static class Platform implements ProfileOwnedTask.Platform {
        final ProfileBrokerHostTest.Fake f=new ProfileBrokerHostTest.Fake();
        final ProfileDisplayCustody custody=new ProfileDisplayCustody();
        final List<String> events=new ArrayList<String>();
        ProfileOwnedTask owner;PublicProfileRecentHistory.Baseline history;
        LongSupplier ioDeadline;
        long started,originalDeadline,firstMixedReadOffset=1383,firstMixedPause=25;
        int removeCalls,deleteCalls,retirementDumps,postReads,globalReads;
        boolean retiring,removed,deleted,mixed=true,transitioned,pausedAfterMixed;
        boolean neverAbsent,moveLeaf,rootReplacement,rootUidChanged,rootCookieMissing,newChild,changedHistory;
        boolean changedIdentity,personalChanges,rootFalse,rootThrows,leafThrows,leafReturnLate,readNeverEnds;
        boolean quarantineAfterMixed,quarantineDuringFinalRead,foreignAfterMixed,rootReturnLate;
        Runnable onRead;
        java.util.concurrent.CountDownLatch mixedReached,continueMixed;
        long subsequentReadCost;
        String raw;
        void checkTime(String reason)throws Exception{
            if(retiring&&ioDeadline!=null&&f.now>=ioDeadline.getAsLong())throw new IOException(reason);
        }
        public ProfileTarget recheck(boolean ready)throws Exception{
            checkTime("PROFILE_READ_DEADLINE");ProfileTarget a=f.recheck(ready);
            ProfileTaskPolicy.need(TARGET.same(a),"PROFILE_INSTALLATION_IDENTITY_CHANGED");return a;
        }
        public void guard()throws Exception{f.guard();}
        public long now(){return f.now;}
        public Object newCookie(){return f.newCookie();}
        public ProfileTaskPolicy.Snapshot snapshot()throws Exception{
            if(retiring){globalReads++;events.add("global@"+(f.now-started));}
            ProfileTaskPolicy.Snapshot original=f.snapshot();
            if(removed&&transitioned&&moveLeaf){
                List<ProfileTaskPolicy.Root> rows=new ArrayList<ProfileTaskPolicy.Root>(original.roots);
                rows.add(ProfileBrokerHostTest.row(900,0,0,300,10,ProfileBrokerHostTest.HOME,false));
                return new ProfileTaskPolicy.Snapshot(rows);
            }
            return original;
        }
        public ProfileTaskPolicy.Recents recents()throws Exception{return f.recents();}
        public String publicRecentsDump()throws Exception{
            if(retiring){
                retirementDumps++;events.add("recents@"+(f.now-started));
                if(removed){
                    postReads++;
                    if(mixed&&!transitioned){
                        f.now=started+firstMixedReadOffset;transitioned=true;
                        if(!neverAbsent){f.app=false;f.recentsApp=false;}
                        if(changedIdentity)f.actual=ProfileBrokerHostTest.target(11,1010367);
                        if(personalChanges){f.personalClosed=true;f.personalAdded=true;}
                        if(foreignAfterMixed)f.foreign=true;
                        if(changedHistory){
                            if(!raw.contains("cc00009"))throw new AssertionError("foreign history fixture anchor");
                            raw=raw.replace("cc00009","cc00008");
                        }
                        if(quarantineAfterMixed)custody.unresolved();
                    }else f.now+=subsequentReadCost;
                    if(readNeverEnds)f.now=started+4000;
                    if(quarantineDuringFinalRead&&deleted)custody.unresolved();
                }
                if(onRead!=null)onRead.run();
                checkTime("PROFILE_RECENTS_DEADLINE");
            }
            return f.recentsApp?leafRecent(raw):raw;
        }
        public List<BackgroundOwnedSingleTask.Task> roots(){
            if(removed&&transitioned&&(rootReplacement||rootUidChanged||rootCookieMissing)&&f.root){
                return Collections.singletonList(new BackgroundOwnedSingleTask.Task(200,7,0,-1,rootUidChanged?1:0,-1,0,
                    rootReplacement?new Object():f.rootToken,
                    rootCookieMissing?Collections.emptyList():Collections.singletonList(f.rootCookie),
                    null,null,null,null,null,false,false));
            }
            return f.roots();
        }
        public List<BackgroundOwnedSingleTask.Task> children(Object token){
            if(removed&&transitioned&&newChild&&f.root)return Collections.singletonList(
                new BackgroundOwnedSingleTask.Task(301,7,10,200,1010367,1010367,1,new Object(),
                    Collections.singletonList(f.launchCookie),ProfileBrokerHostTest.SPLASH,ProfileBrokerHostTest.SPLASH,
                    ProfileBrokerHostTest.HOME,ProfileBrokerHostTest.SPLASH,null,true,true));
            return f.children(token);
        }
        public void createRoot(Object cookie){f.createRoot(cookie);}
        public void bindRoot(Object token,Object cookie){f.bindRoot(token,cookie);}
        public void removeLeaf(Object token)throws Exception{
            if(!f.leafToken.equals(token))throw new AssertionError("wrong actual leaf token");
            removeCalls++;events.add("remove@"+(f.now-started));f.mutations.add("remove_leaf");
            if(leafThrows)throw new IOException("REMOVE_FAILED");
            removed=true;
            if(!mixed&&!neverAbsent){f.app=false;f.recentsApp=false;}
            if(leafReturnLate)f.now=originalDeadline+1;
        }
        public boolean deleteRoot(Object token)throws Exception{
            if(!f.rootToken.equals(token)||f.app)throw new AssertionError("nonempty/replaced root effect");
            deleteCalls++;events.add("delete@"+(f.now-started));f.mutations.add("delete_root");
            if(rootThrows)throw new IOException("DELETE_FAILED");
            if(rootFalse)return false;
            f.root=false;deleted=true;if(rootReturnLate)f.now=started+3100;return true;
        }
        public void pause(){
            if(transitioned&&!pausedAfterMixed){
                f.now+=firstMixedPause;pausedAfterMixed=true;
                if(mixedReached!=null){
                    mixedReached.countDown();
                    try{
                        if(!continueMixed.await(5,java.util.concurrent.TimeUnit.SECONDS))
                            throw new AssertionError("synthetic wait port was not released");
                    }catch(InterruptedException e){Thread.currentThread().interrupt();throw new AssertionError(e);}
                }
            }
            else f.now+=20;
        }
        ProfileOwnedTask active(boolean publicMode)throws Exception{
            raw=before;custody.beforeCreate();
            history=publicMode?new PublicProfileRecentHistory.Baseline(PublicProfileRecentHistory.absence(before,TARGET),f.now):null;
            owner=new ProfileOwnedTask(this,TARGET,ProfileBrokerHostTest.GEN,ProfileBrokerHostTest.REQUEST,7,history);
            owner.prepare();owner.beforeDispatch();f.launch();owner.accepted(0);
            if(!owner.observe())throw new AssertionError("owned leaf not admitted");
            started=f.now;originalDeadline=started+1400;ioDeadline=()->originalDeadline;
            retiring=true;retirementDumps=0;events.clear();return owner;
        }
    }
}
