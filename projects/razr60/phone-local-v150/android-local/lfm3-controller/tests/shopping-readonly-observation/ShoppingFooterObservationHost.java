package org.trillionnium.hepta.local;
import java.nio.file.*;import java.lang.reflect.*;import java.util.*;import org.json.*;
import org.trillionnium.hepta.webprotocol.*;
/** Synthetic boundary changes over the repository fixture; no current private phone inputs. */
public final class ShoppingFooterObservationHost {
 interface Edit {void apply(JSONObject d)throws Exception;}
 static JSONObject originalFirst,originalLast,template,frameTemplate;
 static String anchor,x,y;static int cases,assertions;static JSONArray names=new JSONArray();
 static JSONObject copy(JSONObject o){return new JSONObject(o.toString());}
 static JSONObject row(JSONObject d,String path){return ShoppingReadonlyObservationHost.node(d,path);}
 static void check(boolean value,String why){assertions++;if(!value)throw new AssertionError(why);}
 static void pass(String name){cases++;names.put(name);}
 static JSONObject read(Path p)throws Exception{return new JSONObject(Files.readString(p));}
 static JSONObject capture(JSONObject original,JSONObject before,JSONObject after)throws Exception{
  JSONObject c=copy(original);ShoppingReadonlyObservationHost.recount(before);ShoppingReadonlyObservationHost.recount(after);
  String a=WebDomCanonical.canonical(before),b=WebDomCanonical.canonical(after);
  WebDomStability.Result own=WebDomStability.evaluate(a,b,WebMiActionRegion.POLICY);JSONObject proof=own.evidence();
  // Explicitly synthetic geometry metadata is rebound to this newly generated own-pair proof.
  c.getJSONObject("capture_geometry").put("dom_equal_across_visual_callback",a.equals(b))
   .put("dom_comparison_scope",proof.get("comparison_scope")).put("dom_stability_sha256",WebDomCanonical.sha256(proof));
  return c.put("before_dom_raw_utf8",a).put("dom_raw_utf8",b)
   .put("before_dom_sha256",WebEvidenceJson.sha(a)).put("dom_sha256",WebEvidenceJson.sha(b))
   .put("dom_stability",proof).put("dom_stability_sha256",WebDomCanonical.sha256(proof))
   .put("raw_dom_equal",a.equals(b)).put("comparison_scope",proof.get("comparison_scope"));
 }
 static JSONObject[] pair(Edit firstEdit,Edit lastEdit)throws Exception{
  JSONObject a=copy(template),b=copy(template);
  row(a,x).put("visible_in_viewport",false);row(a,y).put("visible_in_viewport",true);
  row(b,x).put("visible_in_viewport",true);row(b,y).put("visible_in_viewport",false);
  if(firstEdit!=null)firstEdit.apply(a);if(lastEdit!=null)lastEdit.apply(b);
  return new JSONObject[]{capture(originalFirst,a,copy(a)),capture(originalLast,b,copy(b))};
 }
 static JSONObject invoke(JSONObject a,JSONObject b)throws Exception{
  Class<?> use=Class.forName("org.trillionnium.hepta.local.WebShoppingObservationStability$CaptureUse");
  Object purpose=null;for(Object v:use.getEnumConstants())if(v.toString().equals("READONLY_OBSERVATION"))purpose=v;
  Method m=WebShoppingObservationStability.class.getDeclaredMethod("captureDom",JSONObject.class,JSONObject.class,WebEvidenceReceipt.class,WebEvidenceReceipt.class,use);m.setAccessible(true);
  try{return (JSONObject)m.invoke(null,a,b,null,null,purpose);}
  catch(InvocationTargetException e){Throwable t=e.getCause();if(t instanceof Exception)throw(Exception)t;throw(Error)t;}
 }
 static void reject(String name,Edit a,Edit b)throws Exception{
  boolean rejected=false;try{JSONObject[] p=pair(a,b);invoke(p[0],p[1]);}catch(IllegalArgumentException|JSONException expected){rejected=true;}
  check(rejected,name+" must reject");pass(name);
 }
 static void both(String name,Edit e)throws Exception{reject(name,e,e);}
 static void add(JSONObject d,String path,String parent,String tag,JSONArray rect)throws Exception{
  JSONObject n=copy(row(d,x)).put("path",path).put("parent_path",parent).put("tag",tag).put("visible_in_viewport",true).put("rect_css_pixels",rect);
  if("input".equals(tag))n.put("value","");d.getJSONArray("nodes").put(n);
 }
 static JSONObject observed(JSONObject d){return d.getJSONObject("action_region_observations");}

 static void rebind(JSONObject c,String owner)throws Exception{
  WebTaskPurpose p=WebTaskPurpose.fromOwner(owner);JSONObject b=copy(c.getJSONObject("binding"));
  JSONObject auth=new JSONObject(p.authorization.evidence());
  for(Map.Entry<String,Object> e:p.authorization.evidence().entrySet())if(e.getValue()==null)auth.put(e.getKey(),JSONObject.NULL);
  b.put("owner",owner).put("owner_sha256",p.ownerSha256).put("contract_sha256",p.contractSha256).put("authorization",auth)
   .put("goal_kind",p.kind).put("site_policy_id",p.sitePolicyId).put("site_policy_sha256",p.sitePolicySha256).put("initial_url",p.initialUrl);
  c.put("binding",b);WebTaskPurpose.requireBinding(b);
 }
 public static void main(String[] args)throws Exception{
  Path dir=Paths.get(args[0]);originalFirst=read(dir.resolve("raw-first.json")).getJSONObject("capture");
  originalLast=read(dir.resolve("raw-last.json")).getJSONObject("capture");
  template=WebEvidenceJson.parseDom(originalFirst.getString("dom_raw_utf8"));
  frameTemplate=read(dir.resolve("ax-first.json")).getJSONObject("observation");
  anchor=ShoppingReadonlyObservationHost.by(template,"href_resolved","https://webcert.cnmstl.net/cert/grade?sn=3af21034e35011eab3ea00163e068ceb").getString("path");x=anchor+"/0";y=anchor+"/1";
  check(WebTaskPurpose.requireBinding(originalFirst.getJSONObject("binding")).shopping.naturalReadOnlyIntent,"fixture is original price-only purpose");
  JSONObject[] p=pair(null,null);
  if(args.length==2){Path out=Paths.get(args[1]);Files.createDirectory(out);
   Files.writeString(out.resolve("first.json"),p[0].toString());Files.writeString(out.resolve("last.json"),p[1].toString());}
  JSONObject accepted=invoke(p[0],p[1]),scope=accepted.getJSONObject("dom_scope");
  check(scope.has("observed_footer_visibility"),"explicit scoped proof");check(!scope.getBoolean("grants_action_authority"),"no authority");
  check(scope.getJSONArray("outside_changes").length()==2,"only two synthetic visibility changes");
  check(!WebShoppingObservationStability.supportsCaptures(p[0],p[1]),"pre-done overload stays strict");pass("price_only_exact_IMG_swap_without_completion_authority");
  JSONObject[] same=pair(null,d->{row(d,x).put("visible_in_viewport",false);row(d,y).put("visible_in_viewport",true);});
  check(!invoke(same[0],same[1]).getJSONObject("dom_scope").has("observed_footer_visibility")
   &&WebShoppingObservationStability.supportsCaptures(same[0],same[1]),"unchanged footer uses strict proof");pass("no_swap_has_no_footer_exception");
  JSONObject legacyA=copy(p[0]),legacyB=copy(p[1]);
  rebind(legacyA,org.trillionnium.hepta.local.web.WebShoppingGoal.LEGACY_EXPLICIT_OWNER);rebind(legacyB,org.trillionnium.hepta.local.web.WebShoppingGoal.LEGACY_EXPLICIT_OWNER);
  boolean denied=false;try{invoke(legacyA,legacyB);}catch(IllegalArgumentException expected){denied=true;}
  check(denied,"legacy spec/unit purpose cannot use price exception");pass("legacy_specification_and_single_unit_purpose_rejected");
  reject("single_flip_both_visible",null,d->row(d,y).put("visible_in_viewport",true));
  reject("both_hidden",null,d->row(d,x).put("visible_in_viewport",false));
  reject("visibility_string",null,d->row(d,x).put("visible_in_viewport","true"));
  both("third_direct_child",d->add(d,anchor+"/2",anchor,"img",new JSONArray(row(d,x).getJSONArray("rect_css_pixels").toString())));
  both("IMG_descendant",d->add(d,x+"/0",x,"span",new JSONArray(row(d,x).getJSONArray("rect_css_pixels").toString())));
  both("observed_non_IMG",d->row(d,x).put("tag","button"));
  both("observed_role",d->row(d,x).put("role","button"));
  both("observed_label",d->row(d,x).put("aria_label","synthetic button"));
  both("observed_text",d->row(d,x).put("text","synthetic text"));
  both("observed_value",d->row(d,x).put("value","synthetic value"));
  both("observed_link",d->row(d,x).put("href_raw","/synthetic"));
  both("unknown_observed_property",d->row(d,x).put("onclick","synthetic"));
  both("hidden_IMG",d->row(d,x).put("hidden_attr",true));
  both("inert_IMG",d->row(d,x).put("inert_attr",true));
  both("disabled_IMG",d->row(d,x).put("disabled",true));
  reject("changed_parent_href",null,d->row(d,anchor).put("href_resolved","https://invalid.example/"));
  reject("changed_parent_target",null,d->row(d,anchor).put("link_target","_blank"));
  reject("changed_footer_ancestor",null,d->row(d,anchor.substring(0,anchor.lastIndexOf('/'))).put("text","synthetic"));
  reject("changed_IMG_geometry",null,d->row(d,x).getJSONArray("rect_css_pixels").put(0,350));
  both("unequal_IMG_rectangles",d->row(d,y).getJSONArray("rect_css_pixels").put(0,350));
  both("IMG_not_contained_by_parent",d->row(d,anchor).getJSONArray("rect_css_pixels").put(2,360));
  both("footer_branch_overlaps_card_ancestor",d->row(d,anchor.substring(0,anchor.lastIndexOf('/'))).put("rect_css_pixels",new JSONArray(new double[]{0,0,1226,2200})));

  both("other_input_overlap",d->add(d,anchor+"/99",anchor,"input",new JSONArray(row(d,x).getJSONArray("rect_css_pixels").toString())));
  both("foreign_input_overlap",d->add(d,"0/1/0/2/99","0/1/0/2","input",new JSONArray(row(d,x).getJSONArray("rect_css_pixels").toString())));
  both("foreign_link_overlap",d->add(d,"0/1/0/2/99","0/1/0/2","a",new JSONArray(row(d,x).getJSONArray("rect_css_pixels").toString())));
  both("foreign_uppercase_control_role_overlap",d->{add(d,"0/1/0/2/99","0/1/0/2","span",new JSONArray(row(d,x).getJSONArray("rect_css_pixels").toString()));row(d,"0/1/0/2/99").put("role","BUTTON");});
  both("duplicate_exact_certificate_link",d->{JSONObject n=copy(row(d,anchor)).put("path","0/1/0/2/99").put("parent_path","0/1/0/2");d.getJSONArray("nodes").put(n);});
  both("observed_modal",d->observed(d).getJSONObject("top_layer").getJSONArray("modal_paths").put(anchor));
  both("observed_popover",d->observed(d).getJSONObject("top_layer").getJSONArray("popover_paths").put(anchor));
  both("observed_fullscreen",d->observed(d).getJSONObject("top_layer").put("fullscreen_present",true).put("fullscreen_path",anchor));
  both("incomplete_top_layer_observation",d->observed(d).getJSONObject("top_layer").put("selector_api_available",false));
  both("foreign_card_overlay",d->observed(d).getJSONArray("foreign_overlap_paths").put(anchor));
  both("incomplete_card_hit_evidence",d->observed(d).getJSONArray("hit_tests").remove(0));
  String card=observed(template).getJSONObject("candidate").getString("root_path");
  String model=observed(template).getJSONObject("candidate").getString("model_path");
  reject("changed_selected_card_text",null,d->row(d,model).put("text","synthetic other model"));
  reject("changed_selected_card_rect",null,d->row(d,card).getJSONArray("rect_css_pixels").put(0,1));
  reject("changed_selected_card_ancestor",null,d->row(d,card.substring(0,card.lastIndexOf('/'))).put("text","synthetic"));
  reject("changed_selected_region_style",null,d->ShoppingReadonlyObservationHost.style(d,"action_region_observations",card).put("opacity","0.5"));
  reject("HEAD_script_membership",null,d->add(d,"0/0/99","0/0","script",new JSONArray(new int[]{0,0,0,0})));
  JSONObject bad=copy(p[1]);bad.getJSONObject("binding").put("task_id","synthetic-foreign");
  boolean failed=false;try{invoke(p[0],bad);}catch(IllegalArgumentException expected){failed=true;}check(failed,"binding");pass("capture_binding_change_rejected");
  bad=copy(p[1]);bad.put("observer_script_sha256",String.join("",Collections.nCopies(64,"0")));
  failed=false;try{invoke(p[0],bad);}catch(IllegalArgumentException expected){failed=true;}check(failed,"observer");pass("pinned_observer_stays_required");
  bad=copy(p[1]);bad.put("before_dom_raw_utf8",bad.getString("before_dom_raw_utf8")+" ");
  failed=false;try{invoke(p[0],bad);}catch(IllegalArgumentException expected){failed=true;}check(failed,"raw hash");pass("unchanged_own_raw_hash_stays_required");
  bad=copy(p[1]);bad.put("started_elapsed_ms",p[0].getLong("ended_elapsed_ms")-1);
  failed=false;try{invoke(p[0],bad);}catch(IllegalArgumentException expected){failed=true;}check(failed,"order");pass("capture_order_stays_required");
  JSONObject firstBefore=WebEvidenceJson.parseDom(p[0].getString("before_dom_raw_utf8")),firstAfter=copy(firstBefore);
  row(firstAfter,x).put("visible_in_viewport",true);row(firstAfter,y).put("visible_in_viewport",false);
  failed=false;try{invoke(capture(originalFirst,firstBefore,firstAfter),capture(originalLast,copy(firstBefore),copy(firstBefore)));}catch(IllegalArgumentException expected){failed=true;}
  check(failed,"own pair must retain one IMG state");pass("own_pair_visibility_exchange_rejected");

  ShoppingReadonlyObservationHost.a=p[0];ShoppingReadonlyObservationHost.da=WebEvidenceJson.parseDom(p[0].getString("dom_raw_utf8"));
  ShoppingReadonlyObservationHost.fa=frameTemplate;
  JSONArray na=ShoppingReadonlyObservationHost.nativeGraph(false),nb=ShoppingReadonlyObservationHost.nativeGraph(true);
  JSONObject fa=ShoppingReadonlyObservationHost.syntheticFrame(na,false),fb=ShoppingReadonlyObservationHost.syntheticFrame(nb,true);
  String task=p[0].getJSONObject("binding").getString("task_id");
  JSONObject bracket=WebShoppingObservationStability.compareReadonlyObservationBracket(task,fa,na,fb,nb,p[0],p[1],ShoppingReadonlyObservationHost.TARGET);
  check(!bracket.getBoolean("action_permit_created")&&!bracket.getBoolean("business_verified"),"only synthetic read bracket");
  pass("independent_DOM_replay_then_synthetic_complete_native_bracket");
  failed=false;try{WebShoppingObservationStability.compareObservationBracket(task,fa,na,fb,nb,p[0],p[1],ShoppingReadonlyObservationHost.TARGET);}
  catch(IllegalArgumentException expected){failed=true;}check(failed,"final completion bracket stays strict");pass("strict_completion_bracket_rejects_footer_exchange");
  JSONArray changed=new JSONArray(nb.toString());ShoppingReadonlyObservationHost.nativeNode(changed,"0/0").put("description","synthetic changed ancestor");
  JSONObject changedFrame=ShoppingReadonlyObservationHost.syntheticFrame(changed,true);
  failed=false;try{WebShoppingObservationStability.compareReadonlyObservationBracket(task,fa,na,changedFrame,changed,p[0],p[1],ShoppingReadonlyObservationHost.TARGET);}
  catch(IllegalArgumentException expected){failed=true;}check(failed,"actual native comparison not relaxed");pass("native_outside_change_rejected_after_footer_DOM_scope");
  System.out.println(new JSONObject().put("schema","hepta.footer-observation-host.v1").put("all_pass",true).put("cases",cases)
    .put("assertions",assertions).put("case_names",names).put("phone_actions",0).put("business_verified",false)
    .put("current_private_fixtures_used",false).put("complete_native_and_capture_mutations","explicitly_synthetic").toString(2));
 }
}
