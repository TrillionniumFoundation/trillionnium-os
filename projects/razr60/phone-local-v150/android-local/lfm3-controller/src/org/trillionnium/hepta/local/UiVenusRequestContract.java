package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;

/** Pure one-use request boundary; durable claim ordering is also used by the Android consumer. */
public final class UiVenusRequestContract {
    private UiVenusRequestContract() {}
    public static final class Claim {
        public final String id,fixtureSha,nonceSha;
        public final long expiresWallMs;
        private Claim(String id,String fixture,String nonce,long expires){
            this.id=id;fixtureSha=fixture;nonceSha=MobiMindContract.sha(nonce.getBytes(StandardCharsets.UTF_8));expiresWallMs=expires;
        }
        public void requireFresh(long now){need(now>=0&&now<=expiresWallMs,"request expired during input verification");}
    }
    public static Claim validate(byte[] raw,String nonce,long now)throws Exception{
        need(raw!=null&&raw.length>0&&raw.length<=8192&&nonce!=null&&nonce.matches("[0-9a-f]{64}")&&now>=0,"bounded one-use request required");
        Map<String,Object> v=MobiMindContract.jsonObject(raw);
        need(v.keySet().equals(new HashSet<String>(Arrays.asList("schema","nonce","request_id","fixture_sha256","created_wall_ms","expires_wall_ms","deadline_ms","max_tokens"))),"unexpected request fields");
        need("hepta.private-ui-venus-probe.v1".equals(v.get("schema")),"request schema");
        Object stored=v.get("nonce");need(stored instanceof String&&((String)stored).matches("[0-9a-f]{64}"),"request nonce representation");
        need(MessageDigest.isEqual(nonce.getBytes(StandardCharsets.UTF_8),((String)stored).getBytes(StandardCharsets.UTF_8)),"request nonce mismatch");
        String id=text(v,"request_id"),fixture=text(v,"fixture_sha256");need(id.matches("[0-9a-f]{32}")&&fixture.matches("[0-9a-f]{64}"),"request identity");
        long created=number(v,"created_wall_ms"),expires=number(v,"expires_wall_ms");
        need(created>=0&&created<=now+30000&&expires>created&&expires-created<=600000&&now<=expires,"request expiry range");
        need(number(v,"deadline_ms")==UiVenusPins.DEADLINE_MS&&number(v,"max_tokens")==UiVenusPins.MAX_TOKENS,"fixed native budget");
        return new Claim(id,fixture,nonce,expires);
    }
    public interface ClaimStorage {
        void verifyOriginal() throws Exception;
        void createExclusiveClaim(byte[] original) throws Exception;
        void removeOriginal() throws Exception;
        void syncParent() throws Exception;
    }
    /** Any failure leaves the exclusive claim intact. No deletion or retry of that claim is allowed. */
    public static void commitClaim(byte[] original,ClaimStorage storage)throws Exception{
        if(original==null||storage==null)throw new IllegalArgumentException("claim inputs required");
        storage.verifyOriginal();storage.createExclusiveClaim(original.clone());storage.verifyOriginal();storage.removeOriginal();storage.syncParent();
    }
    private static void need(boolean ok,String reason){if(!ok)throw new IllegalArgumentException(reason);}
    private static String text(Map<String,Object> v,String key){Object value=v.get(key);need(value instanceof String,"string required: "+key);return (String)value;}
    private static long number(Map<String,Object> v,String key){Object value=v.get(key);need(value instanceof Integer||value instanceof Long,"integer required: "+key);return ((Number)value).longValue();}
}
