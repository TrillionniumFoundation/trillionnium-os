package org.trillionnium.hepta.webhelper;
import android.content.Context;import org.json.*;import java.io.*;import org.trillionnium.hepta.webprotocol.*;
/** Access wrapper around full production EvidenceFiles. UID role changes are explicit host simulation. */
public final class HelperFilesAccess {
 private final EvidenceFiles files;private final JSONObject binding;
 public HelperFilesAccess(File root,JSONObject b)throws Exception{binding=b;int old=android.os.Process.myUid();android.os.Process.fixtureUid(10484);try{files=new EvidenceFiles(new Context(root));}finally{android.os.Process.fixtureUid(old);}}
 public File root(){return files.root;}
 public File capturePath(String nonce){return new File(files.root,"capture-"+nonce+".json");}
 public byte[] store(String nonce,JSONObject raw)throws Exception{int old=android.os.Process.myUid();android.os.Process.fixtureUid(10484);try{EvidenceFiles.Record r=files.write("capture",nonce,raw);return java.nio.file.Files.readAllBytes(r.path.toPath());}finally{android.os.Process.fixtureUid(old);}}
 public void durable(JSONObject request,String wire)throws Exception{int old=android.os.Process.myUid();android.os.Process.fixtureUid(10484);try{files.journal(new JSONObject().put("schema",WebEvidenceProtocol.JOURNAL_SCHEMA).put("state","active").put("binding",binding).put("binding_sha256",WebEvidenceBinding.sha256(binding)).put("consumed_requests",new JSONObject().put(request.getString("request_nonce"),Jsons.sha(wire))));}finally{android.os.Process.fixtureUid(old);}}
 public void ack(JSONObject request,String wire,boolean live)throws Exception{int old=android.os.Process.myUid();android.os.Process.fixtureUid(10484);try{files.acknowledgeCapture(request,wire,binding,()->{if(!live)throw new IllegalStateException("fixture lease retired");});}finally{android.os.Process.fixtureUid(old);}}
}
