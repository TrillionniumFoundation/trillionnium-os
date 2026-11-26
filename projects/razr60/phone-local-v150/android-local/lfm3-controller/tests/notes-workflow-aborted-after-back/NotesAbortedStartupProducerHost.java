package org.trillionnium.hepta.local;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import org.json.*;

/** Executes the original startup producer on copied historical bytes.
 * Both the unprojected producer record and the one-path Android display
 * projection are retained. This is never a phone-startup or absence claim. */
public final class NotesAbortedStartupProducerHost {
 private static void need(boolean v,String why){if(!v)throw new AssertionError(why);}
 private static String sha(byte[] b)throws Exception{return SessionTerminalHost.sha(b);}
 private static String quote(String value){String array=new JSONArray().put(value).toString();return array.substring(1,array.length()-1);}
 private static JSONObject object(byte[] b)throws Exception{return new JSONObject(new String(b,StandardCharsets.UTF_8));}
 private static JSONObject ref(Path p)throws Exception{
  byte[] b=Files.readAllBytes(p);return new JSONObject().put("path",p.toString()).put("bytes",b.length).put("sha256",sha(b));
 }
 private static byte[] original(JSONObject r)throws Exception{
  byte[] b=Files.readAllBytes(Paths.get(r.getString("path")));need(b.length==r.getLong("bytes")&&sha(b).equals(r.getString("sha256")),"actual original ref");return b;
 }
 public static void main(String[] args)throws Exception{
  if(args.length!=2)throw new IllegalArgumentException("actual input map, new output");
  JSONObject map=object(Files.readAllBytes(Paths.get(args[0])));
  Path out=Paths.get(args[1]).toAbsolutePath();Files.createDirectory(out);Path files=out.resolve("files");Files.createDirectory(files);android.system.Os.chmod(files.toString(),0700);
  byte[] old=original(map.getJSONObject("historical_current_control")),journal=null;
  JSONArray rows=map.getJSONArray("rows");for(int i=0;i<rows.length();i++)if("journal".equals(rows.getJSONObject(i).getString("role")))journal=original(rows.getJSONObject(i).getJSONObject("ref"));
  need(journal!=null,"actual old journal required");JSONObject prior=object(old);need(prior.getInt("app_uid")==android.os.Process.myUid(),"host UID maps to actual owner");
  SessionTerminalHost.write(files.resolve("control-session.json"),old);
  SessionTerminalHost.write(files.resolve("background-session.active.json"),journal);
  SessionTerminalHost.Session session=new SessionTerminalHost.Session(files);
  try{java.lang.reflect.Method recovery=session.getClass().getDeclaredMethod("recoverPreviousSession");recovery.setAccessible(true);recovery.invoke(session);
   need(session.blocked&&!session.pending&&session.lastResult==null&&session.controller.starts==0,"real startup retains failure without replay");
   need(!session.journalQueue.failed(),"real startup persistence succeeded");
  }finally{session.close();}
  Path current=files.resolve("control-session.json"),latch=files.resolve("control-session.interrupted.json");
  byte[] generated=Files.readAllBytes(current);JSONObject control=object(generated),reason=control.getJSONObject("startup_recovery");
  need("interrupted".equals(control.getString("status"))&&control.getBoolean("blocked")&&!control.getBoolean("cleanup_known"),"real blocked current control");
  need(control.getBoolean("background_lease_unreleased")&&!control.getBoolean("web_helper_lease_unreleased"),"actual private lease-file readers remain separate");
  JSONArray preserved=reason.getJSONArray("preserved_records");need(preserved.length()==1,"exact one archive");
  JSONObject archive=preserved.getJSONObject(0);Path origin=Paths.get(archive.getString("path"));
  need(Arrays.equals(old,Files.readAllBytes(origin))&&sha(old).equals(archive.getString("sha256")),"real original archive exact");
  need(Files.exists(latch)&&!object(Files.readAllBytes(latch)).getBoolean("cleanup_known"),"real durable latch");
  need(Arrays.equals(journal,Files.readAllBytes(files.resolve("background-session.active.json"))),"startup does not clear lease");
  // A single path-display IO projection. Every other UTF-8 byte, including
  // producer timestamps, reason, latch references and archive digest is exact.
  String host=archive.getString("path"),android="/data/data/org.trillionnium.hepta.local/files/session-recovery/"+origin.getFileName();
  String text=new String(generated,StandardCharsets.UTF_8);
  String quotedHost=quote(host),quotedAndroid=quote(android);
  need(text.indexOf(quotedHost)>=0&&text.indexOf(quotedHost)==text.lastIndexOf(quotedHost),"unique archive path display field");
  String projected=text.replace(quotedHost,quotedAndroid);
  need(projected.replace(quotedAndroid,quotedHost).equals(text),"one-expression whole-record inverse");
  Path projectedPath=out.resolve("control-android-path-projection.json");
  SessionTerminalHost.write(projectedPath,projected.getBytes(StandardCharsets.UTF_8));
  Path latchCopy=out.resolve("interruption-latch-original.json");SessionTerminalHost.write(latchCopy,Files.readAllBytes(latch));
  Path oldCopy=out.resolve("origin-control-original.json");SessionTerminalHost.write(oldCopy,old);
  JSONObject report=new JSONObject().put("schema","hepta.notes-aborted-startup-host-producer.v1").put("all_pass",true)
   .put("host_only",true).put("phone_startup_proven",false).put("phone_operations",0)
   .put("producer_current_control_unprojected",ref(current)).put("current_control",ref(projectedPath))
   .put("origin_control",ref(oldCopy)).put("actual_producer_archive",ref(origin)).put("interruption_latch",ref(latchCopy))
   .put("actual_producer_latch",ref(latch)).put("exact_original_control_sha256",sha(old))
   .put("path_projection",new JSONObject().put("host_path",host).put("android_display_path",android)
    .put("expression","text.replace(quote(hostPath), quote(androidPath))")
    .put("unique_occurrences",1).put("whole_record_inverse_equal",true))
   .put("actual_startup_member_bodies_unchanged",true).put("existing_acknowledgement_stub_is_refusing",true)
   .put("old_task_replayed",false).put("business_success",false).put("current_absence_proven",false);
  SessionTerminalHost.write(out.resolve("RESULT.json"),report.toString(2).getBytes(StandardCharsets.UTF_8));
  System.out.println(report.toString());
 }
}
