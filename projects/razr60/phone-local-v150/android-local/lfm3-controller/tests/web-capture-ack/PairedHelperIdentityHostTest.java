package org.trillionnium.hepta.local;
import org.json.*;import java.nio.file.*;import java.nio.charset.StandardCharsets;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
public final class PairedHelperIdentityHostTest {
 interface Call {void run()throws Exception;}static int cases,assertions;static JSONArray names=new JSONArray();
 static void need(boolean x,String why){assertions++;if(!x)throw new AssertionError(why);}
 static void test(String n,Call c)throws Exception{c.run();cases++;names.put(n);}
 static void reject(JSONObject o)throws Exception{boolean fail=false;try{ProjectedHelperIdentity.check(WebEvidenceProtocol.HELPER_PACKAGE,o);}catch(Exception e){fail=true;}need(fail,"unapproved helper must reject");}
 public static void main(String[] args)throws Exception{
  String sha="edd439f2432f84ba97ed641eaba5d4f3e2b852f652f90e0ef311ca04ee150313";
  test("exact_signed_single_base_accepted",()->{ProjectedHelperIdentity.check(WebEvidenceProtocol.HELPER_PACKAGE,new JSONObject().put("base",sha));need(true,"accepted");});
  test("original_helper6_rejected",()->reject(new JSONObject().put("base","02360c24c471dcd4be0cbc7c7fdb316a7918d656edd1407d765540b5a3f2f5ff")));
  test("same_signer_different_artifact_rejected",()->reject(new JSONObject().put("base","0"+sha.substring(1))));
  test("missing_base_rejected",()->reject(new JSONObject()));
  test("unexpected_split_rejected",()->reject(new JSONObject().put("base",sha).put("split:extra",sha)));
  test("non_string_hash_rejected",()->reject(new JSONObject().put("base",7)));
  test("truncated_hash_rejected",()->reject(new JSONObject().put("base",sha.substring(1))));
  test("controller_dynamic_hash_retained",()->{ProjectedHelperIdentity.check(WebEvidenceProtocol.CONTROLLER_PACKAGE,new JSONObject().put("base","different current controller hash").put("split:config","dynamic"));need(true,"not pinned to helper");});
  JSONObject r=new JSONObject().put("all_pass",true).put("cases",cases).put("assertions",assertions).put("names",names).put("actual_android_package_manager_executed",false);
  Files.write(Paths.get(args[0]),(r.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);
  System.out.println("paired helper identity "+cases+" / "+assertions);
 }
}
