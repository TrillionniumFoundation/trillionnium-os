package org.trillionnium.hepta.local;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/** Explicit administrative acknowledgement. Never repairs an old task or claims its exit. */
public final class RecoveryJournalTransaction {
    public static final String ACTIVE="control-session.json";
    public static final String LATCH="control-session.interrupted.json";
    public static final String PENDING_PREFIX="control-session.recovery-pending-";
    public static final String IDLE_STATUS="acknowledged_new_session_idle";
    public static final String SCOPE="app_visible_procfs_same_uid";
    private static final String ROOT="session-acknowledgements/";
    private static final String MAGIC="HEPTA-RECOVERY-RECORD-1\n";
    private static final int MAX_RECORD=65536,MAX_PRIOR_BARRIERS=32;
    private static final List<String> FIXED=Collections.unmodifiableList(Arrays.asList(
            ACTIVE,LATCH,ACTIVE+".bak",ACTIVE+".new"));
    private RecoveryJournalTransaction(){}

    /** All publication methods must preserve partial failures and fsync the containing directory. */
    public interface Store {
        byte[] read(String name)throws Exception;
        List<String> pendingBarriers()throws Exception;
        void create(String name,byte[] bytes)throws Exception;
        void replaceActive(byte[] expected,byte[] replacement,String transactionId)throws Exception;
        void removeIfEqual(String name,byte[] expected)throws Exception;
        void sync()throws Exception;
    }
    public interface Check { void check()throws Exception; }
    public interface FreshSample { RecoveryQuiescence.Sample capture()throws Exception; }
    public interface IdleFactory { byte[] create(Acknowledgement acknowledgement)throws Exception; }

    public static final class Acknowledgement {
        public final int uid;
        public final long wallMs;
        public final String transactionId,sessionId,prepareSha256,ackSha256,quiescenceSha256;
        private Acknowledgement(int uid,long wall,String tx,String session,String prepare,String ack,String quiet){
            this.uid=uid;wallMs=wall;transactionId=tx;sessionId=session;
            prepareSha256=prepare;ackSha256=ack;quiescenceSha256=quiet;
        }
    }
    /** Constructible only after rereading every persisted hash in this production verifier. */
    public static final class Proof {
        public final Acknowledgement acknowledgement;
        public final String newIdleSha256,commitSha256;
        private Proof(Acknowledgement ack,String idle,String commit){
            acknowledgement=ack;newIdleSha256=idle;commitSha256=commit;
        }
        public boolean matches(Map<String,Object> value,int uid){
            if(value==null||uid!=acknowledgement.uid)return false;
            Object wall=value.get("updated_wall_ms");
            if(!(wall instanceof Long||wall instanceof Integer)||((Number)wall).longValue()!=acknowledgement.wallMs)return false;
            return IDLE_STATUS.equals(value.get("status"))
                    &&acknowledgement.transactionId.equals(value.get("recovery_transaction_id"))
                    &&acknowledgement.sessionId.equals(value.get("session_id"))
                    &&acknowledgement.prepareSha256.equals(value.get("recovery_prepare_sha256"))
                    &&acknowledgement.ackSha256.equals(value.get("recovery_ack_sha256"))
                    &&acknowledgement.quiescenceSha256.equals(value.get("recovery_quiescence_sha256"))
                    &&"unknown".equals(value.get("old_native_cleanup"))
                    &&"interrupted_not_resumed".equals(value.get("old_session_disposition"))
                    &&SCOPE.equals(value.get("process_inventory_scope"))
                    &&"user_recovery_confirmation".equals(value.get("origin"))
                    &&value.get("task_id")==null&&value.get("instruction_sha256")==null
                    &&value.get("debug_nonce_sha256")==null;
        }
    }

    /** Called once per real confirmation while the App's shared no-child lease and store lock are held. */
    public static Proof acknowledge(Store store,int uid,int pid,String tx,String session,long wall,
            List<RecoveryQuiescence.Sample> initial,Check ownership,FreshSample fresh,
            IdleFactory idleFactory)throws Exception{
        validId(tx);validId(session);
        if(tx.equals(session)||uid<10000||pid<=0||wall<=0)throw new IOException("invalid new session identity");
        RecoveryQuiescence.confirm(initial,uid,pid);
        ownership.check();
        List<String> previous=pendingNames(store);
        List<String> names=new ArrayList<String>(FIXED);names.addAll(previous);
        Map<String,byte[]> originals=new LinkedHashMap<String,byte[]>();
        for(String name:names){ownership.check();originals.put(name,bounded(store.read(name)));}
        String dir=ROOT+tx+"/",barrier=pendingName(tx);
        Map<String,String> b=common("hepta.recovery-pending.v1",uid,tx,session,wall);
        b.put("old_native_cleanup","unknown");b.put("process_inventory_scope",SCOPE);
        byte[] barrierBytes=record(b);
        // No existing byte is changed before this independent barrier is durable.
        store.create(barrier,barrierBytes);store.sync();
        store.create(dir+"BARRIER.record",barrierBytes);
        Map<String,String> prepare=common("hepta.recovery-prepare.v1",uid,tx,session,wall);
        prepare.put("barrier_sha256",sha(barrierBytes));
        prepare.put("original_count",Integer.toString(names.size()));
        prepare.put("old_native_cleanup","unknown");prepare.put("process_inventory_scope",SCOPE);
        for(int i=0;i<names.size();i++){
            byte[] bytes=originals.get(names.get(i));String prefix="original."+i+".";
            prepare.put(prefix+"name",names.get(i));prepare.put(prefix+"present",Boolean.toString(bytes!=null));
            prepare.put(prefix+"bytes",Integer.toString(bytes==null?0:bytes.length));
            prepare.put(prefix+"sha256",bytes==null?"absent":sha(bytes));
        }
        byte[] prepareBytes=record(prepare);store.create(dir+"PREPARE.record",prepareBytes);
        for(int i=0;i<names.size();i++){
            ownership.check();byte[] bytes=originals.get(names.get(i));
            if(bytes!=null)store.create(dir+archiveName(i),bytes);
        }
        store.sync();unchanged(store,originals,previous,barrier,barrierBytes);
        ownership.check();
        List<RecoveryQuiescence.Sample> samples=new ArrayList<RecoveryQuiescence.Sample>(initial);
        samples.add(fresh.capture());
        RecoveryQuiescence.Permit quiet=RecoveryQuiescence.confirm(samples,uid,pid);
        byte[] quietBytes=record(quiet.record());store.create(dir+"QUIESCENCE.record",quietBytes);
        Map<String,String> ack=common("hepta.owner-recovery-ack.v1",uid,tx,session,wall);
        ack.put("origin","user_recovery_confirmation");ack.put("automatic_resume","false");
        ack.put("old_session_disposition","interrupted_not_resumed");
        ack.put("old_native_cleanup","unknown");ack.put("process_inventory_scope",SCOPE);
        ack.put("prepare_sha256",sha(prepareBytes));ack.put("quiescence_sha256",sha(quietBytes));
        byte[] ackBytes=record(ack);store.create(dir+"ACK.record",ackBytes);
        Acknowledgement identity=new Acknowledgement(uid,wall,tx,session,sha(prepareBytes),sha(ackBytes),sha(quietBytes));
        byte[] idle=bounded(idleFactory.create(identity));
        if(idle==null||idle.length==0)throw new IOException("missing new idle journal");
        store.create(dir+"NEW-IDLE.json",idle);
        unchanged(store,originals,previous,barrier,barrierBytes);ownership.check();
        // Old latch and all pending barriers remain active across this atomic replacement.
        store.replaceActive(originals.get(ACTIVE),idle,tx);
        Map<String,String> commit=common("hepta.recovery-commit.v1",uid,tx,session,wall);
        commit.put("prepare_sha256",sha(prepareBytes));commit.put("ack_sha256",sha(ackBytes));
        commit.put("quiescence_sha256",sha(quietBytes));commit.put("new_idle_sha256",sha(idle));
        commit.put("old_native_cleanup","unknown");commit.put("process_inventory_scope",SCOPE);
        byte[] commitBytes=record(commit);store.create(dir+"COMMIT.record",commitBytes);store.sync();
        verifyArchive(store,uid,tx,false);
        ownership.check();
        List<RecoveryQuiescence.Sample> finalSamples=new ArrayList<RecoveryQuiescence.Sample>(samples);
        finalSamples.add(fresh.capture());
        byte[] finalQuietBytes=record(RecoveryQuiescence.confirm(finalSamples,uid,pid).record());
        store.create(dir+"FINAL-QUIESCENCE.record",finalQuietBytes);
        requireEqual(idle,store.read(ACTIVE),"new active journal changed");
        List<String> expected=new ArrayList<String>(previous);expected.add(barrier);Collections.sort(expected);
        if(!pendingNames(store).equals(expected))throw new IOException("pending barriers changed before finalization");
        // No deletion precedes the verified immutable COMMIT. The current barrier is always removed last.
        for(String name:names){
            if(ACTIVE.equals(name))continue;
            ownership.check();store.removeIfEqual(name,originals.get(name));
        }
        ownership.check();store.removeIfEqual(barrier,barrierBytes);store.sync();
        // A crash/failure after deletion but before this final seal still fails startup verification.
        Map<String,String> ready=common("hepta.recovery-ready.v1",uid,tx,session,wall);
        ready.put("commit_sha256",sha(commitBytes));ready.put("new_idle_sha256",sha(idle));
        ready.put("final_quiescence_sha256",sha(finalQuietBytes));
        ready.put("old_native_cleanup","unknown");ready.put("process_inventory_scope",SCOPE);
        ownership.check();
        store.create(dir+"READY.record",record(ready));store.sync();
        return verifyReady(store,uid,tx,idle);
    }

    /** Startup accepts a new idle journal only with the exact completed archive, seal and journal bytes. */
    public static Proof verifyReady(Store store,int uid,String tx,byte[] active)throws Exception{
        Proof proof=verifyArchive(store,uid,tx,true);
        if(!pendingNames(store).isEmpty()||store.read(LATCH)!=null
                ||store.read(ACTIVE+".bak")!=null||store.read(ACTIVE+".new")!=null)
            throw new IOException("recovery still has active barriers or sidecars");
        if(active==null||!proof.newIdleSha256.equals(sha(active)))throw new IOException("idle journal hash mismatch");
        requireEqual(active,store.read(ACTIVE),"active journal changed during verification");
        return proof;
    }

    private static Proof verifyArchive(Store store,int uid,String tx,boolean requireReady)throws Exception{
        validId(tx);String dir=ROOT+tx+"/";
        byte[] prepBytes=required(store,dir+"PREPARE.record"),ackBytes=required(store,dir+"ACK.record");
        byte[] quietBytes=required(store,dir+"QUIESCENCE.record"),idle=required(store,dir+"NEW-IDLE.json");
        byte[] commitBytes=required(store,dir+"COMMIT.record"),barrier=required(store,dir+"BARRIER.record");
        Map<String,String> p=parse(prepBytes),a=parse(ackBytes),c=parse(commitBytes),b=parse(barrier);
        String session=p.get("session_id");validId(session);
        long wall=positiveLong(p.get("wall_ms"));
        checkCommon(p,"hepta.recovery-prepare.v1",uid,tx,session,wall);
        checkCommon(a,"hepta.owner-recovery-ack.v1",uid,tx,session,wall);
        checkCommon(c,"hepta.recovery-commit.v1",uid,tx,session,wall);
        checkCommon(b,"hepta.recovery-pending.v1",uid,tx,session,wall);
        if(b.size()!=8||a.size()!=13||c.size()!=12)throw new IOException("unexpected proof fields");
        if(!"user_recovery_confirmation".equals(a.get("origin"))||!"false".equals(a.get("automatic_resume")))
            throw new IOException("no explicit owner acknowledgement");
        if(!"interrupted_not_resumed".equals(a.get("old_session_disposition")))throw new IOException("old session disposition changed");
        for(Map<String,String> m:Arrays.asList(p,a,b,c)){
            if(!"unknown".equals(m.get("old_native_cleanup"))||!SCOPE.equals(m.get("process_inventory_scope")))
                throw new IOException("old cleanup or visibility scope was changed");
        }
        sameHash(p,"barrier_sha256",barrier);sameHash(a,"prepare_sha256",prepBytes);
        sameHash(a,"quiescence_sha256",quietBytes);sameHash(c,"prepare_sha256",prepBytes);
        sameHash(c,"ack_sha256",ackBytes);sameHash(c,"quiescence_sha256",quietBytes);sameHash(c,"new_idle_sha256",idle);
        RecoveryQuiescence.Permit initialQuiet=RecoveryQuiescence.readRecord(parse(quietBytes),uid);
        int count=positiveInt(p.get("original_count"));
        if(count<FIXED.size()||count>FIXED.size()+MAX_PRIOR_BARRIERS||p.size()!=10+4*count)
            throw new IOException("invalid original record closure");
        List<String> prior=new ArrayList<String>();
        for(int i=0;i<count;i++){
            String prefix="original."+i+".",name=p.get(prefix+"name");
            if(i<FIXED.size()){if(!FIXED.get(i).equals(name))throw new IOException("fixed original name changed");}
            else{validPending(name);if(name.equals(pendingName(tx))||prior.contains(name))throw new IOException("invalid prior barrier");prior.add(name);}
            String present=p.get(prefix+"present");int bytes=nonnegativeInt(p.get(prefix+"bytes"));
            if("true".equals(present)){
                byte[] original=required(store,dir+archiveName(i));
                if(bytes!=original.length)throw new IOException("archive length mismatch");sameHash(p,prefix+"sha256",original);
            }else if(!"false".equals(present)||bytes!=0||!"absent".equals(p.get(prefix+"sha256"))
                    ||store.read(dir+archiveName(i))!=null)throw new IOException("absent original proof differs");
        }
        List<String> sorted=new ArrayList<String>(prior);Collections.sort(sorted);
        if(!sorted.equals(prior))throw new IOException("unordered original barriers");
        if(requireReady){
            Map<String,String> ready=parse(required(store,dir+"READY.record"));
            checkCommon(ready,"hepta.recovery-ready.v1",uid,tx,session,wall);
            if(ready.size()!=11||!"unknown".equals(ready.get("old_native_cleanup"))||!SCOPE.equals(ready.get("process_inventory_scope")))
                throw new IOException("invalid ready seal");
            sameHash(ready,"commit_sha256",commitBytes);sameHash(ready,"new_idle_sha256",idle);
            byte[] finalQuiet=required(store,dir+"FINAL-QUIESCENCE.record");sameHash(ready,"final_quiescence_sha256",finalQuiet);
            RecoveryQuiescence.Permit finalPermit=RecoveryQuiescence.readRecord(parse(finalQuiet),uid);
            if(finalPermit.samples.size()!=initialQuiet.samples.size()+1||finalPermit.pid!=initialQuiet.pid
                    ||finalPermit.startTicks!=initialQuiet.startTicks)throw new IOException("final census has different owner");
            for(int i=0;i<initialQuiet.samples.size();i++){
                RecoveryQuiescence.Sample earlier=initialQuiet.samples.get(i),later=finalPermit.samples.get(i);
                if(earlier.elapsedMs!=later.elapsedMs)throw new IOException("final census does not retain initial interval");
            }
        }
        return new Proof(new Acknowledgement(uid,wall,tx,session,sha(prepBytes),sha(ackBytes),sha(quietBytes)),sha(idle),sha(commitBytes));
    }

    private static void unchanged(Store s,Map<String,byte[]> originals,List<String> old,String barrier,byte[] bytes)throws Exception{
        for(Map.Entry<String,byte[]> e:originals.entrySet())requireEqual(e.getValue(),s.read(e.getKey()),"original record changed");
        requireEqual(bytes,s.read(barrier),"new pending barrier changed");
        List<String> expected=new ArrayList<String>(old);expected.add(barrier);Collections.sort(expected);
        if(!pendingNames(s).equals(expected))throw new IOException("concurrent recovery barrier");
    }
    private static List<String> pendingNames(Store s)throws Exception{
        List<String> names=new ArrayList<String>(s.pendingBarriers());
        if(names.size()>MAX_PRIOR_BARRIERS)throw new IOException("too many pending recovery attempts");
        for(String name:names)validPending(name);Collections.sort(names);
        for(int i=1;i<names.size();i++)if(names.get(i).equals(names.get(i-1)))throw new IOException("duplicate pending barrier");
        return names;
    }
    public static String pendingName(String tx)throws IOException{validId(tx);return PENDING_PREFIX+tx+".record";}
    private static void validPending(String name)throws IOException{
        if(name==null||!name.matches(PENDING_PREFIX+"[0-9a-f]{32}\\.record"))throw new IOException("unrecognized recovery barrier");
    }
    private static String archiveName(int i){return String.format(java.util.Locale.ROOT,"original-%03d.bin",i);}
    private static void validId(String value)throws IOException{if(value==null||!value.matches("[0-9a-f]{32}"))throw new IOException("invalid recovery identity");}
    private static Map<String,String> common(String schema,int uid,String tx,String session,long wall){
        Map<String,String> m=new LinkedHashMap<String,String>();m.put("schema",schema);m.put("uid",Integer.toString(uid));
        m.put("transaction_id",tx);m.put("session_id",session);m.put("wall_ms",Long.toString(wall));
        m.put("automatic_task_replay","false");return m;
    }
    private static void checkCommon(Map<String,String> m,String schema,int uid,String tx,String session,long wall)throws IOException{
        for(Map.Entry<String,String> e:common(schema,uid,tx,session,wall).entrySet())
            if(!e.getValue().equals(m.get(e.getKey())))throw new IOException("proof identity mismatch: "+e.getKey());
    }
    private static byte[] bounded(byte[] bytes)throws IOException{if(bytes!=null&&bytes.length>MAX_RECORD)throw new IOException("record too large");return bytes;}
    private static byte[] required(Store s,String name)throws Exception{byte[] b=bounded(s.read(name));if(b==null)throw new IOException("missing recovery proof");return b;}
    private static void requireEqual(byte[] a,byte[] b,String message)throws IOException{if(!Arrays.equals(a,b))throw new IOException(message);}
    private static void sameHash(Map<String,String> m,String key,byte[] bytes)throws IOException{if(!sha(bytes).equals(m.get(key)))throw new IOException("proof hash mismatch: "+key);}
    private static int nonnegativeInt(String s)throws IOException{long n=number(s);if(n<0||n>MAX_RECORD)throw new IOException("invalid bounded count");return(int)n;}
    private static int positiveInt(String s)throws IOException{int n=nonnegativeInt(s);if(n==0)throw new IOException("empty closure");return n;}
    private static long positiveLong(String s)throws IOException{long n=number(s);if(n<=0)throw new IOException("invalid time");return n;}
    private static long number(String s)throws IOException{try{if(s==null||!s.matches("0|[1-9][0-9]*"))throw new IOException("noncanonical number");return Long.parseLong(s);}catch(NumberFormatException e){throw new IOException("invalid number",e);}}
    public static String sha(byte[] bytes)throws IOException{
        try{byte[] digest=MessageDigest.getInstance("SHA-256").digest(bytes);StringBuilder out=new StringBuilder();
            for(byte b:digest)out.append(String.format(java.util.Locale.ROOT,"%02x",b&255));return out.toString();
        }catch(java.security.NoSuchAlgorithmException e){throw new IOException(e);}
    }
    public static byte[] record(Map<String,String> values)throws IOException{
        StringBuilder b=new StringBuilder(MAGIC);
        for(Map.Entry<String,String> e:new TreeMap<String,String>(values).entrySet()){
            if(!e.getKey().matches("[a-z0-9_.]+")||e.getValue()==null||!e.getValue().matches("[ -~]*")
                    ||e.getValue().indexOf('=')>=0)throw new IOException("noncanonical record field");
            b.append(e.getKey()).append('=').append(e.getValue()).append('\n');
        }
        return bounded(b.toString().getBytes(StandardCharsets.US_ASCII));
    }
    public static Map<String,String> parse(byte[] bytes)throws IOException{
        bounded(bytes);String text=new String(bytes,StandardCharsets.US_ASCII);
        if(!text.startsWith(MAGIC)||!text.endsWith("\n"))throw new IOException("incomplete recovery record");
        Map<String,String> m=new LinkedHashMap<String,String>();
        for(String line:text.substring(MAGIC.length()).split("\n",-1)){
            if(line.isEmpty())continue;int p=line.indexOf('=');
            if(p<=0||m.put(line.substring(0,p),line.substring(p+1))!=null)throw new IOException("duplicate or malformed field");
        }
        if(!Arrays.equals(bytes,record(m)))throw new IOException("noncanonical recovery bytes");return m;
    }
}
