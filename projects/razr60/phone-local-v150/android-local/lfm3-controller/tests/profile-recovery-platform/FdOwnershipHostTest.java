package org.trillionnium.hepta.background;
import android.os.SystemClock;
import android.system.ErrnoException;
import android.system.Os;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.trillionnium.hepta.local.PrivateFilesAccess;

public final class FdOwnershipHostTest {
    private interface Work { byte[] read(int maximum)throws Exception; }
    private interface Checked { void run()throws Exception; }
    private static final List<String> names=new ArrayList<String>();
    private static int assertions;
    private static void need(boolean yes,String reason){assertions++;if(!yes)throw new AssertionError(reason);}
    private static void test(String name,Checked body)throws Exception{body.run();names.add(name);}
    private static Exception failure(Work work,int bound)throws Exception{
        try{work.read(bound);}catch(Exception e){return e;}throw new AssertionError("unexpected read success");
    }
    private static void reset(byte[] bytes){Os.reset(bytes);SystemClock.value=100;}
    private static void closed(){need(Os.opens==1&&Os.closes==1,"one open, exactly one explicit close");}
    private static void both(String name,CheckedProc test)throws Exception{
        for(boolean proc:new boolean[]{true,false}){
            Work work=proc?maximum->AndroidProcProjection.read(100,200,maximum):
                    maximum->PrivateFilesAccess.read(maximum);
            test((proc?"proc_":"private_")+name,()->test.run(work,proc));
        }
    }
    private interface CheckedProc {void run(Work work,boolean proc)throws Exception;}
    public static void main(String[] args)throws Exception{
        both("data_then_os_eof_zero",(work,proc)->{
            byte[] value={1,2,3};reset(value);need(Arrays.equals(work.read(4),value),"all bytes");
            need(Os.eofZero==1,"Os EOF is zero");closed();
        });
        both("empty_eof_zero",(work,proc)->{
            reset(new byte[0]);need(work.read(4).length==0,"empty data");need(Os.eofZero==1,"empty EOF zero");closed();
        });
        both("read_failure_closes",(work,proc)->{
            reset(new byte[]{1});ErrnoException original=new ErrnoException("read",5);Os.readFailure=original;
            need(failure(work,4)==original,"original read failure");closed();
        });
        both("first_fstat_failure_closes",(work,proc)->{
            reset(new byte[]{1});ErrnoException original=new ErrnoException("fstat",5);Os.statFailure=original;
            need(failure(work,4)==original,"original fstat failure");closed();
        });
        both("identity_change_rejects_and_closes",(work,proc)->{
            reset(new byte[]{1});Os.changeIdentity=true;
            need(failure(work,4) instanceof IOException,"identity refusal");closed();
        });
        both("growth_bound_rejects_and_closes",(work,proc)->{
            reset(new byte[]{1,2,3});Os.reportedSize=1;
            Exception e=failure(work,2);
            need((proc?"RECOVERY_PROC_FILE_BOUND":"file grew beyond bound").equals(e.getMessage()),"exact bound gate");closed();
        });
        both("close_failure_prevents_success",(work,proc)->{
            reset(new byte[]{1});ErrnoException closing=new ErrnoException("close",5);Os.closeFailure=closing;
            need(failure(work,4)==closing,"close failure propagates");closed();
        });
        both("read_failure_survives_close_failure",(work,proc)->{
            reset(new byte[]{1});ErrnoException original=new ErrnoException("read",5),closing=new ErrnoException("close",5);
            Os.readFailure=original;Os.closeFailure=closing;
            Exception e=failure(work,4);need(e==original,"primary identity retained");
            need(e.getSuppressed().length==1&&e.getSuppressed()[0]==closing,"close failure suppressed");closed();
        });
        test("proc_deadline_before_open",()->{
            reset(new byte[]{1});SystemClock.value=200;
            need(failure(maximum->AndroidProcProjection.read(100,200,maximum),4).getMessage().equals("RECOVERY_PROC_DEADLINE"),"deadline gate");
            need(Os.opens==0&&Os.closes==0,"no acquired descriptor");
        });
        test("proc_deadline_during_read",()->{
            reset(new byte[]{1});Os.advanceClockAfterRead=200;
            need(failure(maximum->AndroidProcProjection.read(100,200,maximum),4).getMessage().equals("RECOVERY_PROC_DEADLINE"),"deadline during read");closed();
        });
        test("private_path_identity_change",()->{
            reset(new byte[]{1});Os.changePathIdentity=true;
            need(failure(PrivateFilesAccess::read,4).getMessage().equals("file changed during read"),"path gate preserved");closed();
        });
        test("private_wrong_owner",()->{
            reset(new byte[]{1});Os.ownerUid=2000;
            need(failure(PrivateFilesAccess::read,4).getMessage().startsWith("file ownership/type/size/mode mismatch:"),"owner gate retained");closed();
        });
        StringBuilder list=new StringBuilder("[");
        for(String name:names){if(list.length()>1)list.append(',');list.append('"').append(name).append('"');}
        System.out.println("{\"schema\":\"hepta.fd-ownership-host.v1\",\"cases\":"+names.size()+",\"assertions\":"+assertions
                +",\"case_names\":"+list+"],\"phone_contacted\":false,\"android_runtime\":false,"
                +"\"fd_provider\":\"explicit_mock_Os_boundary\",\"close_error_proves_attempt_only\":true}");
    }
}
