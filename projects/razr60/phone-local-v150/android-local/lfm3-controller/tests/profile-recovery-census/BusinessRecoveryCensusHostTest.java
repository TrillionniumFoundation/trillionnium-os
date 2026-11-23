package org.trillionnium.hepta.background;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;

/** Real census/identity decoder with a scripted root procfs boundary. */
public final class BusinessRecoveryCensusHostTest {
    private static final String G="11111111-1111-1111-1111-111111111111";
    private static final long START=543001L,END=START+ProfilePrelaunchRecovery.LIMIT_MS;
    private static final JSONArray cases=new JSONArray();
    private static int checks;
    private static final class Proc implements ProfileRecoveryProcesses.Proc {
        final String mode;final Map<String,Integer> reads=new HashMap<String,Integer>();
        int wave;long time=START+1;
        Proc(String mode){this.mode=mode;}
        int mark(String k){Integer a=reads.get(k);int n=a==null?1:a+1;reads.put(k,n);return n;}
        String[] ids(int... values){return Arrays.stream(values).mapToObj(String::valueOf).toArray(String[]::new);}
        public String[] entries(){
            wave++;
            if(mode.equals("churn"))return wave<=3?ids(50,80,90+wave):ids(50,80);
            if(mode.equals("continuous"))return ids(50,80,90+wave);
            if(mode.equals("stable"))return ids(50,80);
            if(mode.equals("self_missing")&&wave>1)return ids(80);
            if(mode.equals("duplicate")&&wave>1)return ids(50,80,80);
            if(mode.equals("pid_return")||mode.equals("pin_reuse")||mode.equals("pin_gone"))return
                    mode.equals("pin_gone")&&wave>=3?ids(50,80):ids(50,80,91);
            if(mode.startsWith("new_"))return wave==1?ids(50,80):ids(50,80,98);
            return wave==1?ids(50,80,91):ids(50,80);
        }
        void gone(int pid)throws Exception{
            IOException cause=new IOException("native ENOENT parent disappeared");
            ProfileRecoveryProcesses.ProcessGone e=new ProfileRecoveryProcesses.ProcessGone(mode.equals("mismatched_gone")?pid+1:pid,cause);
            if(mode.equals("close_error"))cause.addSuppressed(new IOException("EBADF"));
            if(mode.equals("direct_suppressed"))e.addSuppressed(new IOException("EBADF"));
            if(mode.equals("expired"))time=END;
            throw e;
        }
        public ProfileRecoveryProcesses.Directory directory(int pid)throws Exception{
            int count=mark("dir"+pid);
            if(mode.equals("self_gone")&&pid==50)gone(pid);
            if(mode.equals("pin_gone")&&pid==91&&count==3)gone(pid);
            if(mode.equals("pin_reuse")&&pid==91&&count==3)return new ProfileRecoveryProcesses.Directory(0,1,pid+200);
            if(pid>=91&&pid!=98&&!mode.startsWith("pin_")&&!mode.equals("late_exit")&&!mode.equals("generation_before_exit"))gone(pid);
            return new ProfileRecoveryProcesses.Directory(0,1,pid+100);
        }
        public byte[] read(int pid,String leaf,int maximum)throws Exception{
            int n=mark(leaf+pid);
            if(mode.equals("new_denied")&&pid==98)throw new IOException("EACCES");
            if(mode.equals("new_untyped")&&pid==98)throw new IOException("ENOENT");
            if("stat".equals(leaf)){
                long ticks=mode.equals("self_reused")&&pid==50&&n>2?999:pid+50;
                return ProfileRecoveryHostTest.stat(pid,ticks,0);
            }
            if("status".equals(leaf)){
                if(mode.equals("late_exit")&&pid==91&&n==2)gone(pid);
                int uid=pid==50||pid==91?0:pid==98?2000:10023;
                return ProfileRecoveryHostTest.status(pid,uid,uid,uid,uid);
            }
            if(pid==98&&mode.equals("new_broker"))return ProfileRecoveryHostTest.bytes("sh\0-c\0"+ProfileRecoveryProcesses.BROKER+"\0");
            if(pid==91&&mode.equals("generation_before_exit"))return ProfileRecoveryHostTest.bytes("sh\0-c\0"+G+"\0");
            if(pid==98&&mode.equals("new_runner"))throw new IOException("BUSINESS_MODEL_WORKER_STILL_VISIBLE");
            return ProfileRecoveryHostTest.bytes("ordinary\0");
        }
        public long now(){return time;}
    }
    private static JSONObject fresh(Proc p)throws Exception{
        return ProfileRecoveryProcesses.captureBusiness(p,50,10481,G,START,END);
    }
    private static void check(boolean condition){checks++;if(!condition)throw new AssertionError();}
    private static void reject(String mode,String reason)throws Exception{
        try{fresh(new Proc(mode));}catch(IOException failure){
            check(reason.equals(failure.getMessage()));cases.put(mode);return;
        }
        throw new AssertionError("accepted "+mode);
    }
    public static void main(String[] args)throws Exception{
        Proc old=new Proc("churn");
        try{ProfileRecoveryProcesses.capture(old,50,10481,G,START,END);throw new AssertionError("old scan accepted churn");}
        catch(IOException expected){check("RECOVERY_PROC_CENSUS_UNSTABLE".equals(expected.getMessage()));check(old.wave==3);}
        cases.put("three_whole_scan_restarts_refused");
        JSONObject stable=fresh(new Proc("stable"));check(stable.getInt("process_count")==2);
        check(stable.getInt("inspected_count")==1);cases.put("stable");
        for(String mode:new String[]{"churn","late_exit","pin_gone"}){
            Proc p=new Proc(mode);JSONObject observed=fresh(p);
            check(observed.getBoolean("complete")&&observed.getBoolean("old_creator_absent"));
            check(stable.getString("inventory_sha256").equals(observed.getString("inventory_sha256")));
            check(observed.getInt("process_count")==2&&observed.getInt("inspected_count")==1);
            check(p.wave>=2);cases.put(mode);
        }
        Proc newcomer=new Proc("new_shell");JSONObject added=fresh(newcomer);
        check(added.getInt("process_count")==3&&added.getInt("inspected_count")==2);
        check(newcomer.reads.get("cmdline98")==1&&newcomer.reads.get("stat98")==2);
        cases.put("new_live_shell_fully_read");
        reject("continuous","RECOVERY_PROC_CENSUS_UNSTABLE");reject("pid_return","RECOVERY_PROC_IDENTITY_CHANGED");
        reject("pin_reuse","RECOVERY_PROC_IDENTITY_CHANGED");reject("expired","RECOVERY_PROC_DEADLINE");
        reject("self_gone","RECOVERY_PROC_GONE");reject("self_reused","RECOVERY_PROC_SELF_IDENTITY_CHANGED");
        reject("self_missing","RECOVERY_PROC_SELF_MISSING");reject("new_denied","EACCES");reject("new_untyped","ENOENT");
        reject("mismatched_gone","RECOVERY_PROC_GONE");reject("close_error","RECOVERY_PROC_GONE");
        reject("direct_suppressed","RECOVERY_PROC_GONE");reject("new_broker","RECOVERY_BROKER_OR_CREATOR_STILL_VISIBLE");
        reject("generation_before_exit","RECOVERY_OLD_GENERATION_STILL_VISIBLE");reject("new_runner","BUSINESS_MODEL_WORKER_STILL_VISIBLE");
        reject("duplicate","RECOVERY_PROC_DUPLICATE");
        System.out.println(new JSONObject().put("passed",true).put("cases",cases.length()).put("assertions",checks)
                .put("case_names",cases).put("android_runtime",false).put("phone_operations",0));
    }
}
