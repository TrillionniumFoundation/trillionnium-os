import org.trillionnium.hepta.local.UiVenusRequestContract;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

public final class UiVenusRequestContractHostTest {
    static int assertions;static final String NONCE=repeat('a',64);
    interface Attempt {void run()throws Exception;}
    static String repeat(char c,int n){char[] text=new char[n];java.util.Arrays.fill(text,c);return new String(text);}
    static void yes(boolean v){assertions++;if(!v)throw new AssertionError();}
    static void no(Attempt v)throws Exception{boolean rejected=false;try{v.run();}catch(IllegalArgumentException expected){rejected=true;}yes(rejected);}
    static String request(){return "{\"schema\":\"hepta.private-ui-venus-probe.v1\",\"nonce\":\""+NONCE+"\",\"request_id\":\""+repeat('b',32)+"\",\"fixture_sha256\":\""+repeat('c',64)+"\",\"created_wall_ms\":100000,\"expires_wall_ms\":700000,\"deadline_ms\":300000,\"max_tokens\":1024}";}
    static byte[] bytes(String s){return s.getBytes(StandardCharsets.UTF_8);}
    static final class Store implements UiVenusRequestContract.ClaimStorage {
        final int fail;int stage;boolean original=true,claimed;final List<String> events=new ArrayList<String>();
        Store(int fail){this.fail=fail;}
        void after(String name)throws Exception{events.add(name);if(++stage==fail)throw new Exception("simulated lost acknowledgement at "+name);}
        public void verifyOriginal()throws Exception{if(!original)throw new Exception("original absent");after("verify");}
        public void createExclusiveClaim(byte[] raw)throws Exception{if(claimed)throw new Exception("claim exists");claimed=true;after("exclusive claim");}
        public void removeOriginal()throws Exception{original=false;after("remove original");}
        public void syncParent()throws Exception{after("sync parent");}
    }
    public static void main(String[] args)throws Exception{
        byte[] original=bytes(request());UiVenusRequestContract.Claim c=UiVenusRequestContract.validate(original,NONCE,200000);
        yes(c.id.equals(repeat('b',32))&&c.fixtureSha.equals(repeat('c',64)));c.requireFresh(700000);no(() -> c.requireFresh(700001));
        for(String pair:new String[]{"probe.v1|probe.v2","300000|299999","1024|512","100000|250001","700000|700001"}){
            String[] a=pair.split("\\|");no(() -> UiVenusRequestContract.validate(bytes(request().replace(a[0],a[1])),NONCE,200000));
        }
        no(() -> UiVenusRequestContract.validate(original,repeat('d',64),200000));
        no(() -> UiVenusRequestContract.validate(original,NONCE,700001));
        no(() -> UiVenusRequestContract.validate(bytes(request().replace("\"max_tokens\":1024","\"max_tokens\":1024.0")),NONCE,200000));
        no(() -> UiVenusRequestContract.validate(bytes(request().replace("\"max_tokens\":1024","\"max_tokens\":1024,\"extra\":false")),NONCE,200000));
        no(() -> UiVenusRequestContract.validate(bytes(request().replace("\"max_tokens\":1024","\"max_tokens\":1024,\"max_tokens\":1024")),NONCE,200000));
        Store clean=new Store(0);UiVenusRequestContract.commitClaim(original,clean);yes(clean.claimed&&!clean.original);
        yes(clean.events.toString().equals("[verify, exclusive claim, verify, remove original, sync parent]"));
        try{UiVenusRequestContract.commitClaim(original,clean);throw new AssertionError();}catch(Exception expected){yes(clean.claimed&&!clean.original);}
        for(int stage=1;stage<=5;stage++){
            Store bad=new Store(stage);try{UiVenusRequestContract.commitClaim(original,bad);throw new AssertionError();}catch(Exception expected){yes(bad.stage==stage);}
            yes(bad.claimed==(stage>=2));yes(bad.original==(stage<4));
            if(bad.claimed){try{UiVenusRequestContract.commitClaim(original,bad);throw new AssertionError();}catch(Exception expected){yes(bad.claimed);}}
        }
        System.out.println("UI-Venus one-use request contracts passed: "+assertions+"; no automatic retry or claim removal");
    }
}
