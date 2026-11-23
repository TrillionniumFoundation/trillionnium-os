package org.trillionnium.hepta.background;
import android.os.SystemClock;
import android.system.ErrnoException;
import android.system.Os;
import android.system.OsConstants;
import java.util.ArrayList;
import java.util.List;

public final class ProcErrnoAdapterHostTest {
    private interface Action {void run()throws Exception;}
    private static final List<String> names=new ArrayList<String>();private static int assertions;
    private static void need(boolean x,String why){assertions++;if(!x)throw new AssertionError(why);}
    private static void test(String name,Action action)throws Exception{action.run();names.add(name);}
    private static Exception fail(Action action)throws Exception{
        try{action.run();}catch(Exception e){return e;}throw new AssertionError("unexpected success");
    }
    private static void reset(){Os.reset(new byte[]{7});SystemClock.value=100;}
    private static void read()throws Exception{AndroidProcProjection.read(100,200,4);}
    private static void directory()throws Exception{AndroidProcProjection.directory(100,200);}
    private static ErrnoException error(String source,int n){return new ErrnoException(source,n);}
    private static void gone(Exception e,Throwable cause){
        need(e instanceof ProfileRecoveryProcesses.ProcessGone,"typed disappearance");
        need(((ProfileRecoveryProcesses.ProcessGone)e).pid==123&&e.getCause()==cause,"actual pid/original cause");
        need(e.getSuppressed().length==0,"no hidden suppressed error");
    }
    private static void noFd(){need(Os.opens==0&&Os.closes==0,"no acquired descriptor");}
    public static void main(String[] args)throws Exception{
        test("directory_plain_enoent",()->{
            reset();ErrnoException e=error("lstat",2);Os.directoryFailure=e;gone(fail(ProcErrnoAdapterHostTest::directory),e);noFd();
        });
        test("directory_other_errno_or_suppressed_terminal",()->{
            for(int n:new int[]{3,13,24}){
                reset();ErrnoException e=error("lstat",n);Os.directoryFailure=e;
                need(fail(ProcErrnoAdapterHostTest::directory)==e,"raw directory errno");noFd();
            }
            reset();ErrnoException e=error("lstat",2);e.addSuppressed(error("unknown",5));Os.directoryFailure=e;
            need(fail(ProcErrnoAdapterHostTest::directory)==e,"ambiguous directory remains terminal");noFd();
        });
        test("open_missing_requires_directory_confirmation",()->{
            for(int n:new int[]{2,3}){
                reset();ErrnoException e=error("open",n);Os.openFailure=e;Os.directoryFailure=error("lstat",2);
                gone(fail(ProcErrnoAdapterHostTest::read),e);need(Os.directoryCalls==1,"fresh directory check");noFd();
            }
        });
        test("leaf_missing_but_directory_present_terminal",()->{
            for(int n:new int[]{2,3}){
                reset();ErrnoException e=error("open",n);Os.openFailure=e;
                need(fail(ProcErrnoAdapterHostTest::read)==e,"leaf missing not process absence");
                need(Os.directoryCalls==1,"directory query");noFd();
            }
        });
        test("nontransient_open_has_no_probe",()->{
            for(int n:new int[]{13,24}){
                reset();ErrnoException e=error("open",n);Os.openFailure=e;Os.directoryFailure=error("lstat",2);
                need(fail(ProcErrnoAdapterHostTest::read)==e,"nontransient original");
                need(Os.directoryCalls==0,"no confirmation on denied/exhausted open");noFd();
            }
        });
        test("unknown_confirmation_is_suppressed_on_original",()->{
            reset();ErrnoException a=error("open",2),b=error("lstat",13);Os.openFailure=a;Os.directoryFailure=b;
            Exception e=fail(ProcErrnoAdapterHostTest::read);need(e==a,"original preserved");
            need(e.getSuppressed().length==1&&e.getSuppressed()[0]==b,"confirmation retained");noFd();
        });
        test("suppressed_open_or_confirmation_not_positive",()->{
            reset();ErrnoException a=error("open",2);a.addSuppressed(error("unknown",5));Os.openFailure=a;
            need(fail(ProcErrnoAdapterHostTest::read)==a&&Os.directoryCalls==0,"ambiguous open");noFd();
            reset();a=error("open",2);ErrnoException b=error("lstat",2);b.addSuppressed(error("unknown",5));Os.openFailure=a;Os.directoryFailure=b;
            Exception e=fail(ProcErrnoAdapterHostTest::read);need(e==a,"ambiguous confirmation not typed");
            need(e.getSuppressed().length==1&&e.getSuppressed()[0]==b,"confirmation ambiguity visible");noFd();
        });
        test("deadline_before_and_after_confirmation",()->{
            reset();Os.openFailure=error("open",2);Os.advanceClockAfterOpenFailure=200;
            need("RECOVERY_PROC_DEADLINE".equals(fail(ProcErrnoAdapterHostTest::read).getMessage()),"deadline before confirm");
            need(Os.directoryCalls==0,"no expired probe");noFd();
            reset();Os.openFailure=error("open",3);Os.directoryFailure=error("lstat",2);Os.advanceClockAfterLstat=200;
            need("RECOVERY_PROC_DEADLINE".equals(fail(ProcErrnoAdapterHostTest::read).getMessage()),"deadline after confirm");
            need(Os.directoryCalls==1,"original operation bounded");noFd();
        });
        test("acquired_fd_read_enoent_esrch_terminal",()->{
            for(int n:new int[]{2,3}){
                reset();ErrnoException e=error("read",n);Os.readFailure=e;
                need(fail(ProcErrnoAdapterHostTest::read)==e,"read errno unconverted");
                need(Os.opens==1&&Os.closes==1&&Os.directoryCalls==0,"close without fallback");
            }
        });
        test("acquired_fstat_and_close_errors_terminal",()->{
            reset();ErrnoException e=error("fstat",2);Os.statFailure=e;
            need(fail(ProcErrnoAdapterHostTest::read)==e,"fstat errno retained");need(Os.opens==1&&Os.closes==1,"close on fstat failure");
            reset();e=error("close",2);Os.closeFailure=e;
            need(fail(ProcErrnoAdapterHostTest::read)==e,"close prevents success");need(Os.opens==1&&Os.closes==1,"one close attempt");
        });
        test("read_and_close_errors_both_retained",()->{
            reset();ErrnoException a=error("read",3),b=error("close",5);Os.readFailure=a;Os.closeFailure=b;
            Exception e=fail(ProcErrnoAdapterHostTest::read);need(e==a,"original read");
            need(e.getSuppressed().length==1&&e.getSuppressed()[0]==b,"suppressed close");
            need(Os.opens==1&&Os.closes==1,"explicit close");
        });
        test("normal_read_unchanged",()->{
            reset();byte[] b=AndroidProcProjection.read(100,200,4);need(b.length==1&&b[0]==7,"actual read");
            need(Os.eofZero==1&&Os.opens==1&&Os.closes==1,"EOF zero and close");
        });
        StringBuilder list=new StringBuilder("[");
        for(String n:names){if(list.length()>1)list.append(',');list.append('"').append(n).append('"');}
        System.out.println("{\"schema\":\"hepta.proc-errno-adapter-host.v1\",\"cases\":"+names.size()+",\"assertions\":"+assertions
          +",\"case_names\":"+list+"],\"actual_android_proc_block\":true,\"os_boundary\":\"explicit_mock\","
          +"\"phone_contacted\":false,\"android_runtime\":false,\"pure_census_cases_executed\":0}");
    }
}
