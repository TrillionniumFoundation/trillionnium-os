package org.trillionnium.hepta.local;
import org.json.*;
import org.trillionnium.hepta.webprotocol.WebDomCanonical;
import java.nio.charset.StandardCharsets;
/** Complete synthetic producer-shaped trees; historical retained rows are not complete-pair evidence. */
public final class NativeContainmentDiagnosticHostTest {
 static int cases,checks;static final String ERROR="visible native recommendation escaped its container";
 static void ck(boolean b,String why){checks++;if(!b)throw new AssertionError(why);}
 static JSONObject row(String p,String parent,String cl,int count,int...r){
  return new JSONObject().put("path",p).put("parent_class",parent).put("class",cl)
   .put("package","org.trillionnium.hepta.webhelper").put("window_id",9).put("children",count)
   .put("view_id","").put("text","PRIVATE-TEXT").put("description","PRIVATE-DESCRIPTION")
   .put("bounds",new JSONArray(r)).put("visible",true).put("enabled",true).put("clickable",false)
   .put("editable",false).put("password",false).put("scrollable",false).put("focused",false)
   .put("scroll_actions","[]").put("ime_enter","PRIVATE-IME").put("input_sha256",JSONObject.NULL);
 }
 static JSONArray base(){
  JSONArray a=new JSONArray().put(row("0","","android.webkit.WebView",3,0,0,400,400))
   .put(row("0/0","android.webkit.WebView","android.view.View",0,0,0,100,90)
    .put("text","").put("description",WebShoppingObservationStability.TITLE+" 99元 199元").put("clickable",true))
   .put(row("0/1","android.webkit.WebView","android.view.View",3,0,110,300,300).put("view_id","J_recommend_search"));
  for(int i=0;i<3;i++)a.put(row("0/1/"+i,"android.view.View","android.view.View",0,5,120+i*40,80,150+i*40));
  return a.put(row("0/2","android.webkit.WebView","android.view.View",0,120,0,170,80));
 }
 static JSONArray cp(JSONArray a){return new JSONArray(a.toString());}
 static JSONObject at(JSONArray a,String p){for(int i=0;i<a.length();i++)if(p.equals(a.getJSONObject(i).get("path")))return a.getJSONObject(i);throw new AssertionError(p);}
 static void escape(JSONArray a,String p){at(a,p).put("bounds",new JSONArray(new int[]{5,295,80,330}));}
 static Throwable failure(JSONArray a,JSONArray b,String target,String cl,String msg)throws Exception{
  try{WebShoppingObservationStability.compareNative(a,b,target);throw new AssertionError("expected rejection");}
  catch(Exception x){ck(x.getClass().getName().equals(cl),"exception class "+x);ck(x.getMessage().equals(msg),"exception message "+x);return x;}
 }
 static Throwable geometry(JSONArray a,JSONArray b)throws Exception{return failure(a,b,"0/0","java.lang.IllegalArgumentException",ERROR);}
 static String[] diag(Throwable f,JSONArray a,JSONArray b){return WebShoppingObservationStability.containmentFailureDiagnostic(f,a,b,a.toString(),b.toString(),"0/0");}
 static JSONObject meta(String[] d){ck(d!=null&&d.length==2,"missing diagnostic");return new JSONObject(d[0]);}
 static void absent(Throwable f,JSONArray a,JSONArray b,String target){ck(WebShoppingObservationStability.containmentFailureDiagnostic(f,a,b,a.toString(),b.toString(),target)==null,"earlier rejection mislabelled");}
 static String repeat(char c,int n){char[] r=new char[n];java.util.Arrays.fill(r,c);return new String(r);}
 static JSONObject event(WebObservationTiming t)throws Exception{return t.snapshot().getJSONArray("spans").getJSONObject(0);}
 static WebObservationTiming timing(long[] c){return new WebObservationTiming("synthetic",10,()->c[0]);}
 public static void main(String[] args)throws Exception{
  JSONArray a=base(),b=cp(a);String original=a.toString();
  JSONObject proof=WebShoppingObservationStability.compareNative(a,b,"0/0");
  ck(!proof.getBoolean("action_permit_created")&&!proof.getBoolean("business_verified"),"authority changed");
  ck(original.equals(a.toString()),"success input mutated");cases++;
  a=base();escape(a,"0/1/0");b=cp(a);Throwable f=geometry(a,b);String[] d=diag(f,a,b);JSONObject m=meta(d);
  ck(m.getBoolean("available")&&m.getString("native_path").equals("0/1/0")&&m.getString("side").equals("before"),"first before point");
  ck(!m.getBoolean("container_contains_row")&&!m.getBoolean("original_overlap_evaluated")&&!m.getBoolean("row_overlaps_target"),"short circuit metadata");
  ck(m.getString("before_raw_sha256").equals(WebDomCanonical.sha256Utf8(a.toString())),"raw source hash");
  JSONObject pair=new JSONObject(d[1]);ck(pair.getBoolean("complete")&&pair.getBoolean("contains_page_text"),"private complete label");
  ck(pair.getString("before_snapshot_raw").equals(a.toString())&&pair.getString("after_snapshot_raw").equals(b.toString()),"private raw bytes lost");
  ck(!m.toString().contains("PRIVATE-")&&d[1].contains("PRIVATE-")&&f.getSuppressed().length==1,"public/private separation");
  ck(f.getSuppressed()[0].getStackTrace().length==0&&!f.getSuppressed()[0].toString().contains("PRIVATE-"),"marker export");cases++;
  a=base();b=cp(a);escape(b,"0/1/1");f=geometry(a,b);m=meta(diag(f,a,b));
  ck(m.getString("side").equals("after")&&m.getString("native_path").equals("0/1/1"),"after side");cases++;
  a=base();at(a,"0/1").put("children",11);
  for(int i=3;i<11;i++)a.put(row("0/1/"+i,"android.view.View","android.view.View",0,10,120,20,140));
  escape(a,"0/1/2");escape(a,"0/1/10");b=cp(a);
  JSONArray reverse=new JSONArray();for(int i=a.length()-1;i>=0;i--)reverse.put(a.get(i));a=reverse;
  m=meta(diag(geometry(a,b),a,b));ck(m.getString("native_path").equals("0/1/10"),"TreeMap first failure order");cases++;
  a=base();b=cp(a);at(b,"0/1/0").put("enabled",false);escape(a,"0/1/2");escape(b,"0/1/2");
  f=failure(a,b,"0/0","java.lang.IllegalArgumentException","native recommendation identity or action state changed");absent(f,a,b,"0/0");cases++;
  a=base();at(a,"0/1/0").put("scrollable",true);escape(a,"0/1/1");b=cp(a);
  f=failure(a,b,"0/0","java.lang.IllegalArgumentException","native recommendation carries unsupported input state");absent(f,a,b,"0/0");cases++;
  a=base();escape(a,"0/1/0");b=cp(a);at(b,"0").put("text","PRIVATE-CHANGED");
  f=failure(a,b,"0/0","org.trillionnium.hepta.local.WebNativeObservationChanged","native target, ancestor or outside recommendation node changed: 0");
  absent(f,a,b,"0/0");cases++;
  a=base();JSONObject selected=at(a,"0/0"),foreign=at(a,"0/2");selected.put("path","0/2");foreign.put("path","0/0")
   .put("bounds",new JSONArray(new int[]{5,5,20,20}));escape(a,"0/1/0");b=cp(a);
  f=failure(a,b,"0/2","java.lang.IllegalArgumentException","foreign native node overlaps selected card");absent(f,a,b,"0/2");cases++;
  a=base();escape(a,"0/1/0");b=cp(a);at(b,"0/1/2").put("bounds",new JSONArray().put(0).put(0).put("bad").put(10));
  f=failure(a,b,"0/0","java.lang.IllegalArgumentException","numeric rectangle required");absent(f,a,b,"0/0");cases++;
  a=base();escape(a,"0/1/0");b=cp(a);f=geometry(a,b);
  JSONArray other=cp(a);at(other,"0/1/0").put("text","PRIVATE-DIFFERENT");
  d=WebShoppingObservationStability.containmentFailureDiagnostic(f,a,b,other.toString(),b.toString(),"0/0");
  ck(!meta(d).getBoolean("available")&&d[1]==null,"raw mismatch acquired authority");
  d=WebShoppingObservationStability.containmentFailureDiagnostic(f,cp(a),b,a.toString(),b.toString(),"0/0");
  ck(!meta(d).getBoolean("available")&&d[1]==null,"array identity mismatch accepted");
  String duplicate=a.toString().replace("\"path\":\"0/1/0\"","\"path\":\"0/1/0\",\"path\":\"0/1/0\"");
  ck(!duplicate.equals(a.toString()),"duplicate fixture");
  d=WebShoppingObservationStability.containmentFailureDiagnostic(f,a,b,duplicate,b.toString(),"0/0");
  ck(!meta(d).getBoolean("available")&&d[1]==null,"duplicate raw JSON accepted");cases++;
  a=base();escape(a,"0/1/0");for(int i=0;i<3;i++)at(a,"0/1/"+i).put("text",repeat('x',400000));b=cp(a);f=geometry(a,b);d=diag(f,a,b);
  ck(!meta(d).getBoolean("available")&&meta(d).getString("reason").equals("private_pair_exceeds_cap")&&d[1]==null,"raw budget truncation");cases++;
  a=base();escape(a,"0/1/0");at(a,"0/1/0").put("text",repeat('"',300000));b=cp(a);f=geometry(a,b);
  ck((long)a.toString().getBytes(StandardCharsets.UTF_8).length+b.toString().getBytes(StandardCharsets.UTF_8).length<2097152,"encoded cap fixture");
  d=diag(f,a,b);ck(!meta(d).getBoolean("available")&&meta(d).getString("reason").equals("private_pair_exceeds_cap")&&d[1]==null,"payload budget truncation");cases++;
  final JSONArray aa=base();escape(aa,"0/1/0");final JSONArray bb=cp(aa);final Throwable fail=geometry(aa,bb);
  final String beforeRaw=aa.toString(),afterRaw=bb.toString();final int[] invoked={0},writes={0};final byte[][] stored={null};final String[] filename={null};
  long[] clock={1};WebObservationTiming t=timing(clock);WebObservationTiming.Span s=WebObservationTiming.begin(t,WebObservationTiming.Phase.NATIVE_DOM_BRACKET,10);
  clock[0]=5;WebObservationTiming.failed(s,fail);
  WebObservationTiming.failureGeometry(s,fail,()->{invoked[0]++;return WebShoppingObservationStability.containmentFailureDiagnostic(fail,aa,bb,beforeRaw,afterRaw,"0/0");});
  ck(invoked[0]==0,"provider ran on native worker");clock[0]=12;
  Throwable expired=new IllegalStateException("read deadline expired");
  t.persistPrivateNativePair(expired,(name,bytes)->{writes[0]++;filename[0]=name;stored[0]=bytes.clone();});
  JSONObject e=event(t),ref=e.getJSONObject("native_containment_private_pair");
  ck(invoked[0]==1&&writes[0]==1&&ref.getBoolean("available")&&!ref.getBoolean("native_failure_matches_observation_failure"),"expired outer lost ended native evidence");
  ck(e.getLong("finished_elapsed_ms")==5&&e.getLong("duration_ms")==4&&e.getString("outcome").equals("failed"),"native timing overwritten");
  ck(ref.getInt("bytes")==stored[0].length&&stored[0].length<=2097152&&ref.getString("sha256").equals(WebDomCanonical.sha256Utf8(new String(stored[0],StandardCharsets.UTF_8))),"written bytes binding");
  ck(filename[0].matches("web-native-geometry-pair-[0-9a-f]{32}\\.json")&&!t.snapshot().toString().contains("PRIVATE-")&&!t.snapshot().getBoolean("contains_page_text"),"public body leaked");
  t.persistPrivateNativePair(expired,(name,bytes)->{writes[0]++;});ck(writes[0]==1,"duplicate write");
  at(aa,"0/1/0").put("text","PRIVATE-LATER");
  ck(new JSONObject(new String(stored[0],StandardCharsets.UTF_8)).getString("before_snapshot_raw").equals(beforeRaw),"private string alias");cases++;
  final int[] forbidden={0};long[] c={1};
  for(int kind=0;kind<4;kind++){
   WebObservationTiming tt=timing(c);WebObservationTiming.Span sp=WebObservationTiming.begin(tt,kind==0?WebObservationTiming.Phase.NATIVE_READ:WebObservationTiming.Phase.NATIVE_DOM_BRACKET,10);
   if(kind==2)WebObservationTiming.complete(sp);else if(kind!=1)WebObservationTiming.failed(sp,fail);
   Throwable provided=kind==3?new IllegalArgumentException(ERROR):fail;
   WebObservationTiming.failureGeometry(sp,provided,()->{forbidden[0]++;return new String[]{"{}","PRIVATE"};});
   tt.persistPrivateNativePair(provided,(name,bytes)->{forbidden[0]++;});
  }
  ck(forbidden[0]==0,"wrong phase/pending/success/other throwable provider ran");cases++;
  final JSONArray fa=base();escape(fa,"0/1/0");final JSONArray fb=cp(fa);final Throwable ff=geometry(fa,fb);
  WebObservationTiming tx=timing(c);WebObservationTiming.Span sx=WebObservationTiming.begin(tx,WebObservationTiming.Phase.NATIVE_DOM_BRACKET,10);WebObservationTiming.failed(sx,ff);
  WebObservationTiming.failureGeometry(sx,ff,()->diag(ff,fa,fb));
  Throwable caught=null;try{try{throw ff;}finally{tx.persistPrivateNativePair(ff,(name,bytes)->{throw new AssertionError("synthetic write failure");});}}catch(Throwable got){caught=got;}
  ck(caught==ff&&caught.getClass()==IllegalArgumentException.class&&ERROR.equals(caught.getMessage()),"write failure replaced rejection");
  ck(!event(tx).getJSONObject("native_containment_private_pair").getBoolean("available")
   &&event(tx).getString("error_type").equals("java.lang.IllegalArgumentException"),"write failure marked complete");cases++;
  WebObservationTiming late=timing(c);WebObservationTiming.Span ls=WebObservationTiming.begin(late,WebObservationTiming.Phase.NATIVE_DOM_BRACKET,10);
  final int[] lateWork={0};late.persistPrivateNativePair(expired,(name,bytes)->{lateWork[0]++;});
  WebObservationTiming.failed(ls,ff);WebObservationTiming.failureGeometry(ls,ff,()->{lateWork[0]++;return diag(ff,fa,fb);});
  ck(lateWork[0]==0&&!event(late).has("native_containment_private_pair"),"late worker falsely persisted or waited");cases++;
  WebObservationTiming broken=timing(c);WebObservationTiming.Span bs=WebObservationTiming.begin(broken,WebObservationTiming.Phase.NATIVE_DOM_BRACKET,10);WebObservationTiming.failed(bs,ff);
  WebObservationTiming.failureGeometry(bs,ff,()->{throw new AssertionError("synthetic provider failure");});
  broken.persistPrivateNativePair(ff,(name,bytes)->{throw new AssertionError("writer must not be reached");});
  ck(!event(broken).getJSONObject("native_containment_private_pair").getBoolean("available")&&ERROR.equals(ff.getMessage()),"provider failure replaced original");cases++;
  System.out.println(new JSONObject().put("schema","hepta.native-containment-host.v1").put("all_pass",true)
   .put("cases",cases).put("assertions",checks).put("synthetic_complete_native_pairs",true)
   .put("historical_native_pair_replayed",false).put("phone_actions",0).put("android_service_executed",false));
 }
}
