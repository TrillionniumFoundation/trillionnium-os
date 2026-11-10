package org.trillionnium.hepta.local;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class RecoveryInventoryHostTest {
    private static final int UID=10234,PID=300;
    private static int passed;
    interface Check {void run()throws Exception;}
    private static void ok(boolean value){if(!value)throw new AssertionError();}
    private static void test(String name,Check body)throws Exception{
        body.run();passed++;System.out.println("PASS "+name);
    }
    private static void io(Check body)throws Exception{
        try{body.run();throw new AssertionError("accepted uncertain inventory");}
        catch(IOException expected){}
    }
    private static String stat(int pid,long ticks){
        StringBuilder s=new StringBuilder(pid+" (name with ) and spaces) R");
        for(int i=0;i<18;i++)s.append(" 0");
        return s.append(' ').append(ticks).append("\n").toString();
    }
    private static String status(int pid,int uid){
        return "Name:\tworker\nTgid:\t"+pid+"\nPid:\t"+pid+"\nUid:\t"+uid+"\t"+uid+"\t"+uid+"\t"+uid+"\n";
    }
    private static final class Fake implements RecoveryProcessInventory.Proc {
        String[] names={"self","300"};
        final Map<Integer,RecoveryProcessInventory.Directory> dirs=new HashMap<Integer,RecoveryProcessInventory.Directory>();
        final Map<String,String> files=new HashMap<String,String>();
        final List<String> reads=new ArrayList<String>();
        int selfStatReads,selfDirReads;
        boolean flipTicks,flipDirectory;
        long now=2000;
        Fake(){add(PID,UID,12,100);}
        void add(int pid,int uid,long inode,long ticks){
            dirs.put(pid,new RecoveryProcessInventory.Directory(uid,1,inode));
            files.put(pid+"/stat",stat(pid,ticks));files.put(pid+"/status",status(pid,uid));
        }
        public String[] entries(){return names;}
        public RecoveryProcessInventory.Directory directory(int pid)throws IOException{
            if(pid==PID&&++selfDirReads==4&&flipDirectory)
                return new RecoveryProcessInventory.Directory(UID,1,99);
            RecoveryProcessInventory.Directory d=dirs.get(pid);
            if(d==null)throw new IOException("unclassified or vanished directory");
            return d;
        }
        public String read(int pid,String leaf,int maximum,int uid)throws IOException{
            String key=pid+"/"+leaf;reads.add(key);
            if(pid==PID&&"stat".equals(leaf)&&++selfStatReads>=2&&flipTicks)return stat(pid,101);
            String value=files.get(key);
            if(value==null)throw new IOException("permission denied or missing identity");
            return value;
        }
        public long elapsedMs(){return now;}
    }
    private static RecoveryQuiescence.Sample sample(Fake f)throws IOException{
        return RecoveryProcessInventory.capture(f,UID,PID);
    }
    public static void main(String[] args)throws Exception{
        test("complete-current-process",()->{
            RecoveryQuiescence.Sample s=sample(new Fake());
            ok(s.complete&&s.uid==UID&&s.pid==PID&&s.startTicks==100&&s.otherSameUidProcesses==0);
        });
        test("foreign-owner-never-reads-restricted-status",()->{
            Fake f=new Fake();f.names=new String[]{"300","800"};
            f.dirs.put(800,new RecoveryProcessInventory.Directory(1000,1,88));
            RecoveryQuiescence.Sample s=sample(f);ok(s.otherSameUidProcesses==0);
            for(String key:f.reads)ok(key.startsWith("300/"));
        });
        test("all-extra-same-UID-processes-block",()->{
            Fake f=new Fake();f.add(400,UID,13,200);f.names=new String[]{"300","400"};
            RecoveryQuiescence.Sample s=sample(f);ok(s.otherSameUidProcesses==1);
            try{RecoveryQuiescence.confirm(Arrays.asList(s,new RecoveryQuiescence.Sample(UID,PID,100,2750,1,true),new RecoveryQuiescence.Sample(UID,PID,100,3500,1,true)),UID,PID);throw new AssertionError();}
            catch(IllegalStateException expected){}
        });
        test("unknown-directory-owner-rejected",()->{
            Fake f=new Fake();f.names=new String[]{"300","900"};io(()->sample(f));
        });
        test("same-UID-unreadable-status-rejected",()->{
            Fake f=new Fake();f.add(400,UID,13,200);f.names=new String[]{"300","400"};
            f.files.remove("400/status");io(()->sample(f));
        });
        test("current-unreadable-status-rejected",()->{
            Fake f=new Fake();f.files.remove("300/status");io(()->sample(f));
        });
        test("current-UID-change-rejected",()->{
            Fake f=new Fake();f.files.put("300/status",status(PID,UID+1));io(()->sample(f));
        });
        test("current-missing-from-enumeration-rejected",()->{
            Fake f=new Fake();f.names=new String[]{"self"};io(()->sample(f));
        });
        test("start-ticks-race-rejected",()->{
            Fake f=new Fake();f.flipTicks=true;io(()->sample(f));
        });
        test("directory-identity-race-rejected",()->{
            Fake f=new Fake();f.flipDirectory=true;io(()->sample(f));
        });
        test("duplicate-process-entry-rejected",()->{
            Fake f=new Fake();f.names=new String[]{"300","300"};io(()->sample(f));
        });
        test("short-stat-rejected",()->io(()->RecoveryProcessInventory.startTicks("300 (x) R 0",PID)));
        test("stat-PID-mismatch-rejected",()->io(()->RecoveryProcessInventory.startTicks(stat(301,100),PID)));
        test("zero-start-ticks-rejected",()->io(()->RecoveryProcessInventory.startTicks(stat(PID,0),PID)));
        test("comm-parentheses-are-not-field-separators",()->ok(RecoveryProcessInventory.startTicks(stat(PID,100),PID)==100));
        test("duplicate-UID-status-rejected",()->io(()->RecoveryProcessInventory.verifyStatus(status(PID,UID)+"Uid: 10234 10234 10234 10234\n",PID,UID)));
        test("saved-UID-mismatch-rejected",()->io(()->RecoveryProcessInventory.verifyStatus("Tgid: 300\nPid: 300\nUid: 10234 10234 0 10234\n",PID,UID)));
        test("missing-Tgid-rejected",()->io(()->RecoveryProcessInventory.verifyStatus("Pid: 300\nUid: 10234 10234 10234 10234\n",PID,UID)));
        test("main-thread-await-rejected-before-proc-read",()->{
            android.os.Looper.onMain=true;
            try{RecoveryProcessInventory.awaitInitial(null);throw new AssertionError();}
            catch(IllegalStateException expected){}finally{android.os.Looper.onMain=false;}
        });
        test("interrupted-await-rejected-before-proc-read",()->{
            Thread.currentThread().interrupt();
            try{RecoveryProcessInventory.awaitInitial(null);throw new AssertionError();}
            catch(InterruptedException expected){}finally{Thread.interrupted();}
        });
        System.out.println("TOTAL "+passed);
    }
}
