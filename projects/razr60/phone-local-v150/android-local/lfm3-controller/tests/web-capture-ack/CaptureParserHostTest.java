package org.trillionnium.hepta.webhelper;
import java.nio.file.*;import java.nio.charset.StandardCharsets;import java.util.*;import org.json.*;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;
/** Host parser regression. Historical capture bytes are read verbatim; never granted helper7 authority. */
public final class CaptureParserHostTest {
 interface Checked {void run()throws Exception;}static int cases,checks;static final ArrayList<String> names=new ArrayList<String>();
 static void need(boolean ok,String why){checks++;if(!ok)throw new AssertionError(why);}
 static void test(String name,Checked t)throws Exception{t.run();cases++;names.add(name);}
 static void rejects(Checked t)throws Exception{boolean caught=false;try{t.run();}catch(Exception e){caught=true;}need(caught,"must reject");}
 static String repeat(char c,int n){char[] a=new char[n];Arrays.fill(a,c);return new String(a);}
 public static void main(String[] args)throws Exception{
  if(args.length!=2)throw new IllegalArgumentException("report and historical raw directory");
  test("capture_finite_native_scale_preserved",()->{JSONObject o=Jsons.parseCaptureEvidence("{\"scale\":2.625,\"transform\":[1.0,0,0,1.0],\"id\":7}",4096);need(o.getDouble("scale")==2.625&&o.get("id") instanceof Long,"finite capture numbers");rejects(()->OriginalJsons.parseEvidence("{\"scale\":2.625}",4096));});
  test("capture_dom_string_beyond_legacy_64k_preserved",()->{String d=repeat('x',70000);String raw=new JSONObject().put("dom_raw_utf8",d).toString();need(Jsons.parseCaptureEvidence(raw,WebEvidenceProtocol.MAX_EVIDENCE_BYTES).getString("dom_raw_utf8").equals(d),"full string");rejects(()->OriginalJsons.parseEvidence(raw,WebEvidenceProtocol.MAX_EVIDENCE_BYTES));});
  test("request_and_lease_remain_integer_only",()->{for(String raw:new String[]{"{\"n\":1.5}","{\"n\":1e0}","{\"n\":1.0}"}){rejects(()->Jsons.parse(raw,4096));rejects(()->Jsons.parseEvidence(raw,4096));}need(Jsons.parse("{\"n\":1}",4096).get("n") instanceof Long,"integer type unchanged");});
  test("capture_duplicate_unicode_and_nonfinite_rejected",()->{for(String raw:new String[]{"{\"n\":1,\"n\":2}","{\"n\":NaN}","{\"n\":Infinity}","{\"n\":1e999}","{\"n\":01}","{\"n\":1.}","{\"s\":\"\\u0000\"}","{\"s\":\"\\ud800\"}"})rejects(()->Jsons.parseCaptureEvidence(raw,4096));});
  test("capture_shape_and_budget_remain_bounded",()->{rejects(()->Jsons.parseCaptureEvidence("{\"x\":1} tail",4096));rejects(()->Jsons.parseCaptureEvidence("[]",4096));rejects(()->Jsons.parseCaptureEvidence("{\"x\":1}",5));rejects(()->Jsons.parseCaptureEvidence("{}",WebEvidenceProtocol.MAX_EVIDENCE_BYTES+1));rejects(()->Jsons.parseCaptureEvidence(new JSONObject().put("x",repeat('x',WebEvidenceProtocol.MAX_DOM_BYTES+1)).toString(),WebEvidenceProtocol.MAX_EVIDENCE_BYTES));});
  List<Path> actual=new ArrayList<Path>();try(java.util.stream.Stream<Path> stream=Files.list(Paths.get(args[1]))){stream.filter(p->p.getFileName().toString().matches("raw-[0-9a-f]{64}\\.json")).sorted().forEach(actual::add);}
  need(actual.size()==22,"exact historical22");JSONArray input=new JSONArray();
  for(Path p:actual){byte[] raw=Files.readAllBytes(p);String text=new String(raw,StandardCharsets.UTF_8);
   test("historical_original_"+p.getFileName(),()->{JSONObject parsed=Jsons.parseCaptureEvidence(text,WebEvidenceProtocol.MAX_EVIDENCE_BYTES);need(parsed.getJSONObject("helper_identity").getInt("version_code")==6,"retain original helper6");need(parsed.getJSONObject("capture").getString("dom_raw_utf8").length()>65536,"actual large DOM");need(parsed.getJSONObject("capture").getJSONObject("binding").getString("task_id").equals("81cda99c4edc4df6b9be1db69f7f4ed3"),"original task");rejects(()->OriginalJsons.parseEvidence(text,WebEvidenceProtocol.MAX_EVIDENCE_BYTES));});
   input.put(new JSONObject().put("path",p.toString()).put("bytes",raw.length).put("sha256",Jsons.sha(raw)));
  }
  JSONObject result=new JSONObject().put("all_pass",true).put("cases",cases).put("assertions",checks).put("names",new JSONArray(names)).put("historical_raw_inputs",input).put("historical_inputs_unchanged",true).put("helper7_authority_granted_from_history",false).put("phone_actions",0).put("android_execution",false);
  Files.write(Paths.get(args[0]),(result.toString(2)+"\n").getBytes(StandardCharsets.UTF_8),StandardOpenOption.CREATE_NEW);System.out.println("capture parser "+cases+" cases / "+checks+" assertions");
 }
}
