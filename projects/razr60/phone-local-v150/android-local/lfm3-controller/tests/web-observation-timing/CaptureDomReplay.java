package org.trillionnium.hepta.local;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;
import org.trillionnium.hepta.webprotocol.WebDomCanonical;
/** Immutable saved capture values only; no native snapshots, IPC, phone actions or business proof. */
public final class CaptureDomReplay {
    public static void main(String[] args)throws Exception{
        List<Path> paths=new ArrayList<Path>();
        try(DirectoryStream<Path> stream=Files.newDirectoryStream(Paths.get(args[0]),"raw-*.json")){for(Path path:stream)paths.add(path);}
        List<JSONObject> inputs=new ArrayList<JSONObject>();
        for(Path path:paths){JSONObject raw=new JSONObject(new String(Files.readAllBytes(path),StandardCharsets.UTF_8));
            if(raw.opt("capture") instanceof JSONObject)inputs.add(new JSONObject().put("file",path.getFileName().toString()).put("capture",raw.getJSONObject("capture")));}
        inputs.sort(Comparator.comparingLong(x->x.getJSONObject("capture").getLong("started_elapsed_ms")));
        if(inputs.size()!=4)throw new AssertionError("exact four retained capture inputs required");
        Method exact=WebShoppingObservationStability.class.getDeclaredMethod("captureDom",JSONObject.class,JSONObject.class);
        exact.setAccessible(true);JSONArray pairs=new JSONArray();boolean deterministic=true;
        for(int i=0;i<4;i+=2){
            JSONObject first=inputs.get(i).getJSONObject("capture"),last=inputs.get(i+1).getJSONObject("capture");
            JSONArray runs=new JSONArray();String expectedProof=null,expectedError=null;
            for(int round=0;round<4;round++){
                long start=System.nanoTime();boolean accepted=WebShoppingObservationStability.supportsCaptures(first,last);
                long middle=System.nanoTime();JSONObject proof=null;String error=null;
                try{proof=(JSONObject)exact.invoke(null,first,last);}catch(InvocationTargetException refused){error=refused.getCause().getClass().getName();}
                long end=System.nanoTime();String proofSha=proof==null?null:WebDomCanonical.sha256(proof);
                if(round==0){expectedProof=proofSha;expectedError=error;}
                else deterministic&=Objects.equals(expectedProof,proofSha)&&Objects.equals(expectedError,error);
                deterministic&=accepted==(proof!=null);
                runs.put(new JSONObject().put("round",round).put("accepted",accepted).put("supports_captures_ms",(middle-start)/1000000.0)
                    .put("second_capture_dom_ms",(end-middle)/1000000.0).put("both_ms",(end-start)/1000000.0)
                    .put("proof_sha256",proofSha==null?JSONObject.NULL:proofSha).put("error_type",error==null?JSONObject.NULL:error));
            }
            pairs.put(new JSONObject().put("first_file",inputs.get(i).get("file")).put("last_file",inputs.get(i+1).get("file"))
                .put("first_dom_utf8_bytes",first.getString("dom_raw_utf8").getBytes(StandardCharsets.UTF_8).length)
                .put("last_dom_utf8_bytes",last.getString("dom_raw_utf8").getBytes(StandardCharsets.UTF_8).length).put("runs",runs));
        }
        JSONObject result=new JSONObject().put("schema","hepta.actual-capture-dom-host-timing.v1").put("pairs",pairs)
            .put("same_input_proofs_deterministic",deterministic).put("host_only",true).put("phone_actions",0)
            .put("native_snapshots_available",false).put("native_io_timed",false).put("business_verified",false);
        Files.write(Paths.get(args[1]),(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));
        System.out.println(result.toString());if(!deterministic)throw new AssertionError("same saved input changed proof");
    }
}
