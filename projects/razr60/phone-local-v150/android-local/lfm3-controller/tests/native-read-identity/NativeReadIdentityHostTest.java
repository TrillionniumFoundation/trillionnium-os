package org.trillionnium.hepta.local;

import android.net.LocalSocket;
import android.os.SystemClock;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Locale;
import java.util.Random;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.background.FixedIntentTarget;
import org.trillionnium.hepta.background.ProfileTarget;

/** Runs the production Session.requireLive and the original synthetic background installation fixture. */
public final class NativeReadIdentityHostTest {
    private static int assertions;
    private static void check(boolean ok,String message){
        assertions++;
        if(!ok)throw new AssertionError(message);
    }
    private static String reference(String s)throws Exception{
        byte[] digest=MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8));
        StringBuilder out=new StringBuilder(64);
        for(byte b:digest)out.append(String.format(Locale.ROOT,"%02x",b&255));
        return out.toString();
    }
    private static void checkHashes()throws Exception{
        for(String s:Arrays.asList("", "a", "携程\u0000小米", "🇨🇳🍎", "\ud800", "\udfff", "e\u0301", "é")){
            check(reference(s).equals(FixedIntentTarget.payloadSha256(s)),"kept the original UTF-8 digest");
        }
        boolean refused=false;
        try{FixedIntentTarget.payloadSha256(null);}catch(IllegalArgumentException expected){refused="payload required".equals(expected.getMessage());}
        check(refused,"original null contract");
        boolean[] values=new boolean[256];
        Random deterministic=new Random(213390);
        for(int i=0;i<256;i++){
            StringBuilder s=new StringBuilder();
            for(int j=0;j<(i+1)*2;j++)s.append((char)deterministic.nextInt(65536));
            String current=FixedIntentTarget.payloadSha256(s.toString());
            check(reference(s.toString()).equals(current),"random UTF-16 code units remain byte exact");
            for(int j=0;j<current.length();j+=2)values[Integer.parseInt(current.substring(j,j+2),16)]=true;
        }
        for(boolean seen:values)check(seen,"digest alphabet covers every byte");
    }
    private static JSONArray timings(NativeSearchSession search,int nodes){
        // Three checks for each of N nominal nodes model loop entry, completed refresh and one child-edge check.
        // This isolates Java identity work. It does not simulate Binder time or traversal.
        long[] sorted=new long[9];
        for(int round=-4;round<sorted.length;round++){
            long start=System.nanoTime();
            for(int batch=0;batch<4;batch++)
                for(int i=0;i<nodes*3;i++)search.requireLive(NativeSearchSessionHostTest.START);
            long duration=(System.nanoTime()-start)/4;
            if(round>=0)sorted[round]=duration;
        }
        Arrays.sort(sorted);
        JSONArray samples=new JSONArray();
        for(long n:sorted)samples.put(n);
        return samples;
    }
    public static void main(String[] args)throws Exception{
        NativeProfileIdentityHostTest.workspace=Files.createDirectories(Paths.get(args[0]));
        LocalSocket.reset();SystemClock.now=NativeSearchSessionHostTest.START;
        checkHashes();
        try(NativeSearchSessionHostTest.Fixture f=new NativeSearchSessionHostTest.Fixture()){
            ProfileTarget t=f.env.target,copy=ProfileTarget.fromWire(t.wire());
            ProfileTarget changed=new ProfileTarget(t.profile,t.fullUid+1,t.packageName,t.component,t.versionCode,t.apkHashes,t.signerSha256);
            ProfileTarget version=new ProfileTarget(t.profile,t.fullUid,t.packageName,t.component,t.versionCode+1,t.apkHashes,t.signerSha256);
            ProfileTarget[] targets={t,copy,NativeProfileIdentityHostTest.ctrip(),changed,version,null};
            for(ProfileTarget x:targets)for(ProfileTarget y:targets){
                if(x==null)continue;
                check(x.same(y)==(y!=null&&x.sha256.equals(y.sha256)&&x.wire().equals(y.wire())),"same canonical wire, hash and null semantics");
            }
            check(t.wire().equals(copy.wire())&&t.evidence().equals(copy.evidence()),"wire roundtrip and full installation evidence");
            JSONObject out=new JSONObject().put("profile_sha",t.sha256).put("wire",t.wire()).put("installed_apk_set_sha",t.apkSetSha256)
                    .put("owner_sha",f.nativeTask.goal.ownerSha256).put("selection_sha",NativeAppObservation.selectionSha(f.env.session.selection))
                    .put("goal_sha",f.nativeTask.goal.contractSha256).put("target_sha",f.nativeTask.target.targetSha256)
                    .put("authorization_sha",f.authority.sha256);
            if(args.length>1&&"measure".equals(args[1])){
                out.put("ns_40_nodes_120_calls",timings(f.search,40));out.put("ns_80_nodes_240_calls",timings(f.search,80));
            }
            f.search.requireLive(NativeSearchSessionHostTest.START);
            f.gate.retire();
            boolean denied=false;
            try{f.search.requireLive(NativeSearchSessionHostTest.START);}catch(IllegalArgumentException|IllegalStateException expected){denied=true;}
            check(denied,"live retired gate remains rejected");
            System.out.println(out.put("all_pass",true).put("assertions",assertions).put("phone_operations",0).toString());
        }
    }
}
