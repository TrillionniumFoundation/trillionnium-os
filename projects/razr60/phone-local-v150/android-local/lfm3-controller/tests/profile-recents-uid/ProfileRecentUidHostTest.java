package org.trillionnium.hepta.background;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
public final class ProfileRecentUidHostTest {
    interface Run { void run() throws Exception; }
    private static int cases, assertions;
    private static void yes(boolean value,String message){assertions++;if(!value)throw new AssertionError(message);}
    private static void test(Run r)throws Exception{r.run();cases++;}
    private static final String HEAD="ACTIVITY MANAGER RECENT TASKS (dumpsys activity recents)\n"
        +"mRecentsUid=1000\nmRecentsComponent=ComponentInfo{a/b}\nmFreezeTaskListReordering=false\n"
        +"mFreezeTaskListReorderingPendingTimeout=false\n  Recent tasks:\n";
    private static String row(int ordinal,int id,String user,String uid,String suffix){
        return "  * Recent #"+ordinal+": Task{abc"+id+" #"+id+" type=standard}\n"
            +"    userId="+user+" effectiveUid="+uid+suffix+"\n"
            +"    taskId="+id+" rootTaskId="+id+"\n    Activities=[]\n";
    }
    private static String dump(int user,String uid){
        return HEAD+row(0,100,Integer.toString(user),uid,
            " mCallingUid=2000 mUserSetupComplete=true mCallingPackage=com.android.shell mCallingFeatureId=null");
    }
    private static ProfileTaskPolicy.Recent accept(int user,String text,int uid)throws Exception{
        ProfileTaskPolicy.Recents r=ProfileTaskPolicy.Recents.parse(dump(user,text));
        yes(r.rows.size()==1&&r.ids.equals(r.rows.keySet()),"full set");
        ProfileTaskPolicy.Recent v=r.rows.get(100);
        yes(v.user==user&&v.uid==uid,"wrong decoded identity");
        return v;
    }
    private static void reject(String code,Run r)throws Exception{
        try{r.run();throw new AssertionError("expected "+code);}
        catch(ProfileTaskPolicy.Refusal e){yes(code.equals(e.code),"wrong refusal: "+e.code);}
        catch(BackgroundOwnedSingleTask.Refusal e){yes(code.equals(e.code),"wrong original refusal: "+e.code);}
    }
    private static void synthetic()throws Exception{
        test(()->{accept(0,"0",0);accept(0,"1000",1000);accept(0,"10367",10367);accept(10,"1010367",1010367);});
        test(()->{accept(0,"u0a0",10000);accept(0,"u0a481",10481);accept(10,"u10a367",1010367);accept(0,"u0a79999",89999);});
        test(()->{accept(10,"u10s0",1000000);accept(10,"u10s1000",1001000);accept(10,"u10s9999",1009999);});
        test(()->{accept(0,"u0ai0",90000);accept(0,"u0ai8999",98999);accept(0,"u0ai9000",99000);
            accept(0,"u0i1",99001);accept(10,"u10i999",1099999);});
        test(()->{accept(21474,"u21474a73647",Integer.MAX_VALUE);accept(21474,"2147483647",Integer.MAX_VALUE);});
        test(()->{
            for(String token:new String[]{"-1","+1000","01000","u00a481","u0a0481","u0s1000",
                "u10s10000","u0a80000","u0ai9001","u0i0","u0i1000","u0x481","u0a-1",
                "u0a1more","u0a481/u1a481","u21474a73648","u21475s0"})
                reject("PROFILE_RECENT_UID_INVALID",()->ProfileTaskPolicy.Recents.parse(dump(0,token)));
            for(String token:new String[]{"2147483648","u999999999999999999999a1","u0a2147483648"})
                reject("PROFILE_INTEGER_INVALID",()->ProfileTaskPolicy.Recents.parse(dump(0,token)));
        });
        test(()->{
            reject("PROFILE_RECENT_USER_UNKNOWN",()->ProfileTaskPolicy.Recents.parse(dump(0,"")));
            reject("PROFILE_RECENT_USER_UNKNOWN",()->ProfileTaskPolicy.Recents.parse(dump(0,"u0a481").replace("userId=0","userId=?")));
            reject("PROFILE_RECENT_USER_UNKNOWN",()->ProfileTaskPolicy.Recents.parse(dump(0,"u0a481").replace("userId=0","userId=00")));
        });
        test(()->reject("PROFILE_RECENT_UID_USER_MISMATCH",()->ProfileTaskPolicy.Recents.parse(dump(10,"u0a367"))));
        test(()->{
            reject("RECENTS_UID_DETAIL_INVALID",()->ProfileTaskPolicy.Recents.parse(dump(0,"u0a481")+"    userId=0 effectiveUid=u0a481\n"));
        });
        test(()->{
            reject("PROFILE_RECENT_IDENTITY_DUPLICATE",()->ProfileTaskPolicy.Recents.parse(
                dump(0,"u0a481").replace(" mCallingUid=2000"," userId=0 mCallingUid=2000")));
            reject("PROFILE_RECENT_IDENTITY_DUPLICATE",()->ProfileTaskPolicy.Recents.parse(
                dump(0,"u0a481").replace(" mCallingUid=2000"," effectiveUid=u0a481 mCallingUid=2000")));
        });
        test(()->{
            ProfileTaskPolicy.Recents r=ProfileTaskPolicy.Recents.parse(
                dump(0,"u0a481").replace("mCallingUid=2000","mCallingUid=u10a367"));
            yes(r.rows.get(100).uid==10481&&r.rows.get(100).user==0,"caller UID substituted");
        });
        test(()->reject("RECENTS_TASK_DETAIL_INCOMPLETE",()->ProfileTaskPolicy.Recents.parse(
            dump(0,"u0a481").replace("    Activities=[]\n",""))));
        test(()->{
            ProfileTarget target=ProfileBrokerHostTest.target(10,1010367);
            ProfileTaskPolicy.Recents.parse(dump(0,"u0a367")).requireDedicatedEmpty(target);
            yes(true,"personal user ignored by explicit profile gate");
            reject("PROFILE_ALREADY_HAS_RECENT_TASK",()->ProfileTaskPolicy.Recents.parse(
                dump(10,"u10a367")).requireDedicatedEmpty(target));
        });
        test(()->{
            ProfileTarget target=ProfileBrokerHostTest.target(10,1010367);
            String mixed=HEAD+row(0,100,"0","u0a367"," mCallingUid=2000")
                +row(1,300,"10","u10a367"," mCallingUid=2000");
            ProfileTaskPolicy.Recents r=ProfileTaskPolicy.Recents.parse(mixed);
            r.requireOnlyOwned(target,300);yes(r.rows.size()==2,"mixed users missing");
            reject("PROFILE_FOREIGN_RECENT_TASK",()->ProfileTaskPolicy.Recents.parse(
                mixed.replace("effectiveUid=u10a367","effectiveUid=u10a368")).requireOnlyOwned(target,300));
        });
        System.out.println("{\"schema\":\"hepta.profile-recent-uid-host.v1\",\"passed\":true,\"cases\":"+cases
            +",\"assertions\":"+assertions+",\"framework_fixtures_synthetic\":true,\"phone_contacted\":false}");
    }
    private static String sha(byte[] value)throws Exception{
        StringBuilder b=new StringBuilder();
        for(byte v:MessageDigest.getInstance("SHA-256").digest(value))b.append(String.format(java.util.Locale.ROOT,"%02x",v&255));
        return b.toString();
    }
    private static void actual(String path)throws Exception{
        byte[] bytes=Files.readAllBytes(Paths.get(path));
        yes("0f28f6726e1e292971fe7ecdbcf67053f8185318a129a79f02351a607e367467".equals(sha(bytes)),"actual dump identity");
        ProfileTaskPolicy.Recents r=ProfileTaskPolicy.Recents.parse(new String(bytes,StandardCharsets.UTF_8));
        yes(r.rows.size()==22&&r.rows.keySet().equals(r.ids),"actual complete recents set");
        Set<Integer> uids=new HashSet<Integer>();
        for(ProfileTaskPolicy.Recent row:r.rows.values()){yes(row.user==0,"actual user changed");uids.add(row.uid);}
        yes(uids.equals(new HashSet<Integer>(Arrays.asList(1000,10280,10282,10367,10480,10481))),"actual UID values");
        r.requireDedicatedEmpty(ProfileBrokerHostTest.target(10,1010367));
        yes(true,"actual profile absence");
        System.out.println("{\"schema\":\"hepta.profile-recent-uid-actual-replay.v1\",\"passed\":true,\"rows\":22,\"assertions\":"
            +assertions+",\"raw_sha256\":\""+sha(bytes)+"\",\"phone_contacted\":false,\"native_business_verified\":false}");
    }
    public static void main(String[] args)throws Exception{
        if(args.length==2&&"actual".equals(args[0]))actual(args[1]);
        else if(args.length==0)synthetic();
        else throw new IllegalArgumentException("optional actual dump argument required");
    }
}
