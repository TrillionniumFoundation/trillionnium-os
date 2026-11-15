import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.trillionnium.hepta.local.RecoveryJournalTransaction;
import org.trillionnium.hepta.local.RecoveryQuiescence;
import org.trillionnium.hepta.local.SessionRecovery;

/** Executes the production transaction with an explicit fault-injected file adapter, not Android fsync. */
public final class RecoveryAcknowledgementHostTest {
    static final int UID=10234,PID=1222;
    static final String TX=repeat('a'),SESSION=repeat('b'),OLD=repeat('c'),TX2=repeat('d'),SESSION2=repeat('e');
    static int assertions;
    static void check(boolean condition,String what){assertions++;if(!condition)throw new AssertionError(what);}
    static String repeat(char c){char[] s=new char[32];Arrays.fill(s,c);return new String(s);}
    static byte[] bytes(String s){return s.getBytes(StandardCharsets.UTF_8);}
    static byte[] copy(byte[] b){return b==null?null:b.clone();}
    interface Attempt{void run()throws Exception;}
    static void rejects(Attempt run,String what)throws Exception{boolean failed=false;try{run.run();}catch(Exception expected){failed=true;}check(failed,what);}
    static final class FakeStore implements RecoveryJournalTransaction.Store {
        final Map<String,byte[]> files=new LinkedHashMap<String,byte[]>();
        final List<String> events=new ArrayList<String>();
        int step,failAt=-1;boolean after,partial;String activeAttempt;
        FakeStore(){
            files.put("control-session.json",bytes("original running journal\n"));
            files.put("control-session.interrupted.json",bytes("original interruption latch\n"));
            files.put("control-session.json.bak",bytes("original atomic backup\n"));
            files.put("control-session.json.new",bytes("original partial new journal\n"));
            files.put("control-session.recovery-pending-"+OLD+".record",new byte[]{0,1,2});
            files.put("session-acknowledgements/"+OLD+"/PREPARE.record",bytes("prior partial immutable attempt"));
            files.put("task-runs/original/native/receipt.pending",bytes("native pending evidence, never touched"));
        }
        void before(String event)throws Exception{step++;events.add(event);if(step==failAt&&!after)throw new IOException("injected before "+event);}
        void after(String event)throws Exception{if(step==failAt&&after)throw new IOException("injected after "+event);}
        public byte[] read(String n)throws Exception{before("read:"+n);byte[] b=copy(files.get(n));after("read:"+n);return b;}
        public List<String> pendingBarriers()throws Exception{before("list");List<String> a=new ArrayList<String>();for(String n:files.keySet())if(n.startsWith(RecoveryJournalTransaction.PENDING_PREFIX))a.add(n);after("list");return a;}
        public void create(String n,byte[] b)throws Exception{
            before("create:"+n);if(files.containsKey(n))throw new IOException("immutable file already exists");
            if(n.startsWith(RecoveryJournalTransaction.PENDING_PREFIX))activeAttempt=n.substring(RecoveryJournalTransaction.PENDING_PREFIX.length(),n.length()-".record".length());
            if(partial&&step==failAt){files.put(n,Arrays.copyOf(b,b.length/2));throw new IOException("injected partial write");}
            files.put(n,copy(b));after("create:"+n);
        }
        public void replaceActive(byte[] expected,byte[] b,String tx)throws Exception{
            before("replace");if(!Arrays.equals(expected,files.get(RecoveryJournalTransaction.ACTIVE)))throw new IOException("active compare failed");
            files.put(RecoveryJournalTransaction.ACTIVE,copy(b));after("replace");
        }
        public void removeIfEqual(String n,byte[] expected)throws Exception{
            before("remove:"+n);
            boolean committed=activeAttempt!=null&&files.containsKey("session-acknowledgements/"+activeAttempt+"/COMMIT.record");
            check(committed,"no active evidence is removed before COMMIT");
            if(!Arrays.equals(expected,files.get(n)))throw new IOException("remove compare failed");files.remove(n);after("remove:"+n);
        }
        public void sync()throws Exception{before("sync");after("sync");}
    }
    static List<RecoveryQuiescence.Sample> initial(){return Arrays.asList(sample(100,0,true),sample(850,0,true),sample(1600,0,true));}
    static RecoveryQuiescence.Sample sample(long elapsed,int others,boolean complete){return new RecoveryQuiescence.Sample(UID,PID,99,elapsed,others,complete);}
    static RecoveryJournalTransaction.Proof acknowledge(FakeStore s,String tx,String session)throws Exception{
        final long[] next={2400};
        return RecoveryJournalTransaction.acknowledge(s,UID,PID,tx,session,123456L,initial(),()->{},
                ()->{RecoveryQuiescence.Sample v=sample(next[0],0,true);next[0]+=800;return v;},
                a->bytes("idle:"+a.transactionId+":"+a.sessionId+":"+a.prepareSha256+":"+a.ackSha256));
    }
    static Map<String,Object> idleMap(RecoveryJournalTransaction.Proof proof){
        RecoveryJournalTransaction.Acknowledgement a=proof.acknowledgement;
        Map<String,Object> m=new LinkedHashMap<String,Object>();m.put("schema","hepta.local-session.v1");
        m.put("status",RecoveryJournalTransaction.IDLE_STATUS);m.put("state","new idle; old cleanup unknown");
        m.put("app_uid",UID);m.put("updated_wall_ms",a.wallMs);m.put("task_id",null);m.put("instruction_sha256",null);m.put("debug_nonce_sha256",null);
        m.put("origin","user_recovery_confirmation");m.put("pending",false);m.put("running",false);m.put("blocked",false);m.put("cleanup_known",true);
        m.put("external_model",false);m.put("automatic_resume",false);m.put("session_id",a.sessionId);m.put("recovery_transaction_id",a.transactionId);
        m.put("recovery_prepare_sha256",a.prepareSha256);m.put("recovery_ack_sha256",a.ackSha256);m.put("recovery_quiescence_sha256",a.quiescenceSha256);
        m.put("old_native_cleanup","unknown");m.put("old_session_disposition","interrupted_not_resumed");m.put("process_inventory_scope",RecoveryJournalTransaction.SCOPE);return m;
    }
    static Map<String,byte[]> snapshot(FakeStore s){Map<String,byte[]> out=new LinkedHashMap<String,byte[]>();for(Map.Entry<String,byte[]> e:s.files.entrySet())out.put(e.getKey(),copy(e.getValue()));return out;}
    static void originalSafety(FakeStore s,Map<String,byte[]> before,String tx)throws Exception{
        check(Arrays.equals(before.get("task-runs/original/native/receipt.pending"),s.files.get("task-runs/original/native/receipt.pending")),"old native pending never changed");
        check(Arrays.equals(before.get("session-acknowledgements/"+OLD+"/PREPARE.record"),s.files.get("session-acknowledgements/"+OLD+"/PREPARE.record")),"prior partial attempt never changed");
        String[] names={"control-session.json","control-session.interrupted.json","control-session.json.bak","control-session.json.new","control-session.recovery-pending-"+OLD+".record"};
        for(int i=0;i<names.length;i++)if(!Arrays.equals(before.get(names[i]),s.files.get(names[i]))){
            String archive="session-acknowledgements/"+tx+"/"+String.format(Locale.ROOT,"original-%03d.bin",i);
            check(Arrays.equals(before.get(names[i]),s.files.get(archive)),"changed original already archived byte-for-byte: "+names[i]);
        }
    }
    static void faultMatrix()throws Exception{
        FakeStore base=new FakeStore();acknowledge(base,TX,SESSION);int count=base.step;
        String dir="session-acknowledgements/"+TX+"/";
        check(base.events.contains("create:"+dir+"PREPARE.record")&&base.events.contains("create:"+dir+"ACK.record")
                &&base.events.contains("replace")&&base.events.contains("create:"+dir+"COMMIT.record")
                &&base.events.contains("create:"+dir+"READY.record"),"exercise every required production transaction phase");
        int attempts=0;
        for(boolean after:new boolean[]{false,true})for(int point=1;point<=count;point++){
            FakeStore s=new FakeStore();Map<String,byte[]> originals=snapshot(s);s.failAt=point;s.after=after;
            boolean failed=false;try{acknowledge(s,TX,SESSION);}catch(Exception expected){failed=true;}
            check(failed,"each before/after fault is reached: "+after+":"+point);s.failAt=-1;
            originalSafety(s,originals,TX);
            boolean ready=false;try{RecoveryJournalTransaction.verifyReady(s,UID,TX,s.files.get(RecoveryJournalTransaction.ACTIVE));ready=true;}catch(Exception expected){}
            if(ready)check(s.files.containsKey("session-acknowledgements/"+TX+"/READY.record"),"only complete sealed attempt can qualify after late read fault");
            Map<String,byte[]> immutable=snapshot(s);
            RecoveryJournalTransaction.Proof retry=acknowledge(s,TX2,SESSION2);
            check(retry.acknowledgement.transactionId.equals(TX2),"a new explicit acknowledgement uses a new attempt");
            for(Map.Entry<String,byte[]> e:immutable.entrySet())if(e.getKey().startsWith("session-acknowledgements/"))
                check(Arrays.equals(e.getValue(),s.files.get(e.getKey())),"retry preserves every earlier partial or committed artifact");
            attempts++;
        }
        for(int point=1;point<=count;point++)if(base.events.get(point-1).startsWith("create:")){
            FakeStore s=new FakeStore();Map<String,byte[]> original=snapshot(s);s.failAt=point;s.after=true;s.partial=true;
            rejects(()->acknowledge(s,TX,SESSION),"partial create rejected");s.failAt=-1;originalSafety(s,original,TX);
            rejects(()->RecoveryJournalTransaction.verifyReady(s,UID,TX,s.files.get(RecoveryJournalTransaction.ACTIVE)),"partial write never yields a valid proof");
            acknowledge(s,TX2,SESSION2);attempts++;
        }
        System.out.println("fault-injected production transaction attempts="+attempts+" (including fresh explicit retries)");
    }
    static void proofsAndQuiescence()throws Exception{
        FakeStore s=new FakeStore();Map<String,byte[]> original=snapshot(s);RecoveryJournalTransaction.Proof p=acknowledge(s,TX,SESSION);originalSafety(s,original,TX);
        check(s.pendingBarriers().isEmpty(),"all archived active barriers removed only after commit");
        Map<String,Object> fields=idleMap(p);
        check(SessionRecovery.evaluate(fields,UID,false,p).allowNewTask,"verified new idle accepted");
        check(!SessionRecovery.evaluate(fields,UID).allowNewTask,"identical fields alone never authorize acknowledgement");
        check(!SessionRecovery.evaluate(fields,UID,true,p).allowNewTask,"latch still overrides proof");
        FakeStore retained=new FakeStore();RecoveryJournalTransaction.Proof completed=acknowledge(retained,TX,SESSION);
        byte[] completedIdle=copy(retained.files.get(RecoveryJournalTransaction.ACTIVE));
        byte[] completedArchive=copy(retained.files.get("session-acknowledgements/"+TX+"/NEW-IDLE.json"));
        retained.files.put(RecoveryJournalTransaction.LATCH,bytes("post-install handoff retained; old native cleanup unknown"));
        rejects(()->RecoveryJournalTransaction.verifyReady(retained,UID,TX,retained.files.get(RecoveryJournalTransaction.ACTIVE)),"late cancellation barrier defeats an otherwise valid committed idle on restart");
        check(!SessionRecovery.evaluate(idleMap(completed),UID,true,completed).allowNewTask,"late handoff retention stays blocked despite old valid proof");
        check(Arrays.equals(completedIdle,retained.files.get(RecoveryJournalTransaction.ACTIVE)),"late retention does not rewrite committed idle bytes");
        RecoveryJournalTransaction.Proof retry=acknowledge(retained,TX2,SESSION2);
        check(retry.acknowledgement.transactionId.equals(TX2),"explicit retry after retained close has a new identity");
        check(Arrays.equals(completedArchive,retained.files.get("session-acknowledgements/"+TX+"/NEW-IDLE.json")),"retry preserves earlier completed administrative history");
        check(!SessionRecovery.evaluate(fields,UID+1,false,p).allowNewTask,"proof cannot change UID");
        Map<String,Object> changedWall=new LinkedHashMap<String,Object>(fields);changedWall.put("updated_wall_ms",123457L);
        check(!SessionRecovery.evaluate(changedWall,UID,false,p).allowNewTask,"proof cannot change owner confirmation time");
        for(String key:new String[]{"recovery_transaction_id","session_id","recovery_prepare_sha256","recovery_ack_sha256","recovery_quiescence_sha256","old_native_cleanup","old_session_disposition","process_inventory_scope","origin"}){
            Map<String,Object> bad=new LinkedHashMap<String,Object>(fields);bad.put(key,"changed");
            check(!SessionRecovery.evaluate(bad,UID,false,p).allowNewTask,"altered identity refused: "+key);
        }
        Map<String,byte[]> intact=snapshot(s);
        for(String name:new ArrayList<String>(s.files.keySet()))if(name.startsWith("session-acknowledgements/"+TX+"/")){
            s.files.remove(name);rejects(()->RecoveryJournalTransaction.verifyReady(s,UID,TX,s.files.get(RecoveryJournalTransaction.ACTIVE)),"missing artifact refused: "+name);s.files.put(name,copy(intact.get(name)));
            byte[] broken=copy(intact.get(name));if(broken.length>0)broken[0]^=1;else broken=new byte[]{1};s.files.put(name,broken);
            rejects(()->RecoveryJournalTransaction.verifyReady(s,UID,TX,s.files.get(RecoveryJournalTransaction.ACTIVE)),"changed artifact refused: "+name);s.files.put(name,copy(intact.get(name)));
        }
        s.files.put(RecoveryJournalTransaction.PENDING_PREFIX+"malformed",new byte[0]);
        rejects(()->RecoveryJournalTransaction.verifyReady(s,UID,TX,s.files.get(RecoveryJournalTransaction.ACTIVE)),"unknown barrier stays blocking");
        RecoveryQuiescence.Permit quiet=RecoveryQuiescence.confirm(initial(),UID,PID);
        check(quiet.lastElapsedMs-quiet.firstElapsedMs==1500,"stable span is measured");
        check("unknown".equals(RecoveryQuiescence.readRecord(quiet.record(),UID).record().get("old_native_cleanup")),"quiet interval never proves old exit");
        for(RecoveryQuiescence.Sample replacement:Arrays.asList(sample(1600,1,true),sample(1600,0,false),
                new RecoveryQuiescence.Sample(UID+1,PID,99,1600,0,true),new RecoveryQuiescence.Sample(UID,PID+1,99,1600,0,true),
                new RecoveryQuiescence.Sample(UID,PID,100,1600,0,true),sample(850,0,true),sample(1599,0,true))){
            List<RecoveryQuiescence.Sample> bad=new ArrayList<RecoveryQuiescence.Sample>(initial());bad.set(2,replacement);
            rejects(()->RecoveryQuiescence.confirm(bad,UID,PID),"uncertain identity or insufficient interval refuses acknowledgement");
        }
        rejects(()->RecoveryQuiescence.confirm(initial().subList(0,2),UID,PID),"two samples insufficient");
        Map<String,String> extra=new LinkedHashMap<String,String>(quiet.record());extra.put("claimed_old_exit","0");
        rejects(()->RecoveryQuiescence.readRecord(extra,UID),"unrecognized cleanup assertion rejected");
        FakeStore changed=new FakeStore();final int[] checks={0};
        rejects(()->RecoveryJournalTransaction.acknowledge(changed,UID,PID,TX,SESSION,123L,initial(),()->{
            if(++checks[0]==8)changed.files.put("control-session.json",bytes("concurrent owner"));
        },()->sample(2400,0,true),a->bytes("idle")),"concurrent journal mutation refused");
        check(changed.files.containsKey("control-session.interrupted.json"),"concurrent owner does not clear latch");
        FakeStore cancel=new FakeStore();final int[] calls={0};
        rejects(()->RecoveryJournalTransaction.acknowledge(cancel,UID,PID,TX,SESSION,123L,initial(),()->{
            if(++calls[0]==9)throw new IOException("reservation cancelled");
        },()->sample(2400,0,true),a->bytes("idle")),"cancelled shared lease fails closed");
        check(cancel.files.containsKey("control-session.interrupted.json"),"precommit cancellation retains latch");
    }
    public static void main(String[] args)throws Exception{proofsAndQuiescence();faultMatrix();System.out.println("RecoveryAcknowledgementHostTest assertions="+assertions+" PASS (host file-adapter contract only)");}
}
