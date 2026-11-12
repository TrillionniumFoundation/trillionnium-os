package org.trillionnium.hepta.local;

import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.local.web.WebShoppingGoal;
import org.trillionnium.hepta.webprotocol.WebSitePolicy;
import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Bounded read-only projection of an actual complete DOM-v3 record.
 * No Mi CSS selector, SKU, price, or currency is invented from a search index.
 * Only explicit visible HTML Product/Offer semantics can produce detail data;
 * a page without those semantics remains partial until its actual layout is reviewed.
 * This projection alone cannot grant an AX action or task completion.
 */
final class MiPublicProductPage {
    static final String SCHEMA="hepta.mi-public-product-page.v1";
    static final String DOM_SCHEMA="hepta.fixed-top-document-dom.v3";
    private static final Pattern MODEL=Pattern.compile("^(?:(?:Xiaomi|小米)[ ]*(?:(?:路由器|Router)[ ]*)?)?AX3000T$",Pattern.CASE_INSENSITIVE);
    private static final Pattern AMOUNT=Pattern.compile("^(?:(?:人民币|CNY|RMB|¥|￥)[ ]*)?((?:0|[1-9][0-9]{0,7})(?:\\.[0-9]{1,2})?)(?:[ ]*元)?$");
    private static final Pattern CONDITIONAL=Pattern.compile("券|会员|补贴|定金|分期|每月|月供|预售|预约|满减|到手|折后|需登录|需领|秒杀|限时|首购");
    final String url,phase;
    final boolean modalPresent;
    final List<Link> productLinks;
    final Detail detail;
    final List<String> missing;
    private final Map<String,JSONObject> nodes;
    private final Map<String,Integer> ids;
    static final class Link {
        final String path,id,label,hrefRaw,hrefResolved,target,modelPath;
        final List<String> visibleTexts;
        Link(JSONObject node,JSONObject model,List<String> texts,String resolved)throws Exception {
            path=text(node,"path");id=text(node,"id");label=text(model,"text");
            hrefRaw=text(node,"href_raw");hrefResolved=resolved;target=text(node,"link_target");
            modelPath=text(model,"path");visibleTexts=Collections.unmodifiableList(new ArrayList<String>(texts));
        }
        Map<String,Object> evidence(){
            Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("anchor_dom_path",path);out.put("anchor_dom_id",id);
            out.put("model_dom_path",modelPath);out.put("model_label",label);out.put("href_raw",hrefRaw);
            out.put("href_resolved",hrefResolved);out.put("link_target",target);out.put("visible_texts",visibleTexts);
            out.put("navigation_authorized",false);out.put("product_detail_verified",false);return out;
        }
    }
    static final class Detail {
        final String productPath,offerPath,modelPath,modelLabel,pricePath,priceRaw,currencyPath,currencyRaw;
        final String amountDecimal,priceKind,skuPath,skuRaw;
        final List<String> visibleProductTexts,visibleOfferTexts;
        final boolean exactPublicPrice;
        Detail(String product,String offer,JSONObject model,JSONObject price,JSONObject currency,
               JSONObject sku,List<String> productTexts,List<String> offerTexts,String amount,String kind)throws Exception {
            productPath=product;offerPath=offer;modelPath=text(model,"path");modelLabel=text(model,"text");
            pricePath=text(price,"path");priceRaw=text(price,"text");currencyPath=text(currency,"path");currencyRaw=text(currency,"text");
            skuPath=sku==null?null:text(sku,"path");skuRaw=sku==null?null:text(sku,"text");
            amountDecimal=amount;priceKind=kind;exactPublicPrice="public_exact_display".equals(kind);
            visibleProductTexts=Collections.unmodifiableList(new ArrayList<String>(productTexts));
            visibleOfferTexts=Collections.unmodifiableList(new ArrayList<String>(offerTexts));
        }
        Map<String,Object> evidence(){
            Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("product_dom_path",productPath);out.put("offer_dom_path",offerPath);
            out.put("model_dom_path",modelPath);out.put("model_raw",modelLabel);out.put("price_dom_path",pricePath);
            out.put("displayed_price_raw",priceRaw);out.put("amount_decimal",amountDecimal);out.put("currency_dom_path",currencyPath);
            out.put("currency_raw",currencyRaw);out.put("currency","CNY");out.put("price_kind",priceKind);
            out.put("sku_dom_path",skuPath);out.put("visible_sku_raw",skuRaw);out.put("selected_variant",null);out.put("quantity",null);
            out.put("visible_product_texts",visibleProductTexts);out.put("visible_offer_texts",visibleOfferTexts);
            out.put("exact_configuration_verified",false);out.put("specifications_verified",false);
            out.put("native_visibility_verified",false);out.put("model_navigation_verified",false);
            out.put("task_completion_verified",false);return out;
        }
    }
    private MiPublicProductPage(String url,String phase,boolean modal,List<Link> links,Detail detail,List<String> missing,
                                Map<String,JSONObject> nodes,Map<String,Integer> ids){
        this.url=url;this.phase=phase;modalPresent=modal;productLinks=Collections.unmodifiableList(new ArrayList<Link>(links));
        this.detail=detail;this.missing=Collections.unmodifiableList(new ArrayList<String>(missing));this.nodes=nodes;this.ids=ids;
    }
    static MiPublicProductPage read(WebShoppingGoal goal,WebSitePolicy policy,String committed,JSONObject dom)throws Exception{
        need(goal!=null&&policy!=null&&dom!=null,"immutable goal/policy and actual DOM required");
        need(DOM_SCHEMA.equals(text(dom,"schema"))&&Boolean.FALSE.equals(dom.get("truncated"))
                &&dom.getJSONArray("truncation_reasons").length()==0,"complete exact DOM-v3 required");
        need(committed.equals(text(dom,"href"))&&policy.origin.equals(text(dom,"origin"))&&policy.allowsMainFrame(committed),
                "same approved committed product route required");
        need("complete".equals(text(dom,"ready_state")),"public page still loading");
        JSONArray rows=dom.getJSONArray("nodes");need(rows.length()>0&&rows.length()<=1536,"bounded actual DOM nodes");
        Map<String,JSONObject> nodes=new LinkedHashMap<String,JSONObject>();Map<String,Integer> ids=new HashMap<String,Integer>();
        for(int i=0;i<rows.length();i++){
            JSONObject n=rows.getJSONObject(i);String path=text(n,"path"),id=text(n,"id");
            need(path.matches("0(?:/[0-9]{1,5}){0,32}")&&!nodes.containsKey(path),"unique complete DOM ancestry");
            for(String k:Arrays.asList("tag","role","text","aria_label","item_type","item_prop","aria_hidden","aria_modal","aria_selected","aria_checked","aria_pressed"))
                text(n,k);
            for(String k:Arrays.asList("visible_in_viewport","disabled","item_scope","hidden_attr","inert_attr"))
                need(n.get(k) instanceof Boolean,"typed DOM boolean: "+k);
            for(String k:Arrays.asList("href_raw","href_resolved","link_target"))
                need(n.get(k)==JSONObject.NULL||n.get(k) instanceof String&&((String)n.get(k)).length()<=4096,"bounded anchor field");
            nodes.put(path,n);if(!id.isEmpty())ids.put(id,ids.containsKey(id)?ids.get(id)+1:1);
        }
        for(JSONObject n:nodes.values()){
            String path=text(n,"path");Object parent=n.get("parent_path");
            need("0".equals(path)?parent==JSONObject.NULL:parent instanceof String&&nodes.containsKey(parent)
                    &&path.substring(0,path.lastIndexOf('/')).equals(parent),"recorded DOM parent required");
        }
        List<String> missing=new ArrayList<String>();List<Link> links=new ArrayList<Link>();Detail detail=null;boolean modal=false;
        for(JSONObject n:nodes.values())if(visible(n,nodes)&&("dialog".equals(text(n,"tag"))
                ||"dialog".equals(text(n,"role"))||"alertdialog".equals(text(n,"role"))||"true".equals(text(n,"aria_modal"))))modal=true;
        WebSitePolicy.Route route=policy.classify(committed);
        String phase=route==WebSitePolicy.Route.INITIAL_PUBLIC_SEARCH?"official_public_search":"official_product_detail";
        if(modal)missing.add("visible_modal_or_consent_requires_stop");
        if(route==WebSitePolicy.Route.INITIAL_PUBLIC_SEARCH){
            for(JSONObject n:nodes.values()){
                if(!"a".equals(text(n,"tag"))||!visible(n,nodes)||n.get("href_raw")==JSONObject.NULL
                        ||n.get("href_resolved")==JSONObject.NULL||n.get("link_target")==JSONObject.NULL)continue;
                String href=policy.observedProductLink(committed,text(n,"href_raw"),text(n,"href_resolved"),text(n,"link_target"));
                if(href==null)continue;
                List<JSONObject> names=matchingModel(nodes,text(n,"path"));
                if(names.size()!=1||nestedControl(nodes,text(n,"path")))continue;
                List<String> texts=visibleTexts(nodes,text(n,"path"),64);
                if(texts.isEmpty()||containsTransaction(texts))continue;
                links.add(new Link(n,names.get(0),texts,href));
            }
            if(links.size()!=1)missing.add("unique_actual_AX3000T_anchor_not_observed");
            if(links.size()==1&&(links.get(0).id.isEmpty()||!Integer.valueOf(1).equals(ids.get(links.get(0).id))))
                missing.add("unique_DOM_id_to_native_AX_bridge_missing");
            missing.add("detail_page_not_observed");
        }else{
            List<JSONObject> products=new ArrayList<JSONObject>();
            for(JSONObject n:nodes.values())if(visible(n,nodes)&&Boolean.TRUE.equals(n.get("item_scope"))
                    &&typeIs(n,"Product")&&insideMain(n,nodes))products.add(n);
            if(products.size()!=1)missing.add("unique_visible_explicit_Product_scope_missing");
            else{
                JSONObject product=products.get(0);String productPath=text(product,"path");
                List<JSONObject> models=matchingModel(nodes,productPath),offers=new ArrayList<JSONObject>();
                for(JSONObject n:nodes.values())if(descendant(productPath,text(n,"path"))&&visible(n,nodes)
                        &&Boolean.TRUE.equals(n.get("item_scope"))&&typeIs(n,"Offer")&&prop(n,"offers"))offers.add(n);
                if(models.size()!=1)missing.add("unique_same_product_model_missing");
                if(offers.size()!=1)missing.add("unique_visible_Offer_scope_missing");
                if(models.size()==1&&offers.size()==1){
                    String offerPath=text(offers.get(0),"path");
                    List<JSONObject> prices=properties(nodes,offerPath,"price"),currencies=properties(nodes,offerPath,"priceCurrency");
                    List<JSONObject> skus=properties(nodes,productPath,"sku");
                    if(prices.size()!=1||currencies.size()!=1)missing.add("unique_visible_price_and_currency_missing");
                    else{
                        JSONObject price=prices.get(0),currency=currencies.get(0);Matcher amount=AMOUNT.matcher(text(price,"text"));
                        boolean cny=Arrays.asList("CNY","RMB","人民币","元").contains(text(currency,"text"));
                        if(!amount.matches()||!cny||struck(price,nodes))missing.add("visible_current_CNY_amount_not_verified");
                        else{
                            BigDecimal number=new BigDecimal(amount.group(1));need(number.signum()>0,"nonpositive public price");
                            List<String> productTexts=visibleTexts(nodes,productPath,256),offerTexts=visibleTexts(nodes,offerPath,96);
                            String joined=join(productTexts);String kind=CONDITIONAL.matcher(joined).find()?"conditional":
                                    joined.contains("起")?"starting_price":"public_exact_display";
                            detail=new Detail(productPath,offerPath,models.get(0),price,currency,skus.size()==1?skus.get(0):null,
                                    productTexts,offerTexts,amount.group(1),kind);
                            if(!detail.exactPublicPrice)missing.add("price_is_starting_or_conditional");
                            if(goal.singleUnitRequested)missing.add("requested_single_unit_and_selected_variant_unverified");
                            if(goal.specificationsRequested)missing.add("requested_hardware_specifications_unverified");
                        }
                    }
                }
            }
        }
        return new MiPublicProductPage(committed,phase,modal,links,detail,missing,nodes,ids);
    }
    Map<String,Object> evidence(){
        Map<String,Object> out=new LinkedHashMap<String,Object>();out.put("schema",SCHEMA);out.put("current_native_url",url);
        out.put("phase",phase);out.put("visible_modal_present",modalPresent);List<Object> links=new ArrayList<Object>();
        for(Link link:productLinks)links.add(link.evidence());out.put("actual_product_link_candidates",links);
        out.put("detail_projection",detail==null?null:detail.evidence());out.put("missing",missing);
        out.put("search_index_used",false);out.put("price_or_SKU_filled_from_goal",false);out.put("business_verified",false);
        out.put("layout_visibility_is_screen_proof",false);return out;
    }
    boolean uniqueId(String id){return id!=null&&!id.isEmpty()&&Integer.valueOf(1).equals(ids.get(id));}
    private static List<JSONObject> matchingModel(Map<String,JSONObject> nodes,String root)throws Exception{
        List<JSONObject> out=new ArrayList<JSONObject>();for(JSONObject n:nodes.values())
            if(descendant(root,text(n,"path"))&&visible(n,nodes)&&MODEL.matcher(text(n,"text")).matches())out.add(n);return out;
    }
    private static List<JSONObject> properties(Map<String,JSONObject> nodes,String root,String property)throws Exception{
        List<JSONObject> out=new ArrayList<JSONObject>();for(JSONObject n:nodes.values())
            if(descendant(root,text(n,"path"))&&visible(n,nodes)&&prop(n,property)&&!text(n,"text").isEmpty())out.add(n);return out;
    }
    private static List<String> visibleTexts(Map<String,JSONObject> nodes,String root,int max)throws Exception{
        List<String> out=new ArrayList<String>();for(JSONObject n:nodes.values())if(descendant(root,text(n,"path"))&&visible(n,nodes)){
            String s=text(n,"text");if(!s.isEmpty()){need(out.size()<max,"complete product text budget exceeded");out.add(s);}}
        return out;
    }
    private static boolean nestedControl(Map<String,JSONObject> nodes,String root)throws Exception{
        for(JSONObject n:nodes.values()){String path=text(n,"path");if(path.equals(root)||!descendant(root,path))continue;
            if(Arrays.asList("a","button","input","select","textarea").contains(text(n,"tag"))
                    ||Arrays.asList("button","checkbox","radio","textbox").contains(text(n,"role")))return true;}
        return false;
    }
    private static boolean containsTransaction(List<String> texts){String s=join(texts);
        return s.contains("购买")||s.contains("加购")||s.contains("购物车")||s.contains("付款")||s.contains("支付")
                ||s.contains("领券")||s.contains("登录")||s.contains("同意")||s.contains("下单");}
    private static boolean insideMain(JSONObject node,Map<String,JSONObject> nodes)throws Exception{
        JSONObject n=node;while(n!=null){if("main".equals(text(n,"tag"))||"main".equals(text(n,"role")))return true;
            Object p=n.get("parent_path");n=p instanceof String?nodes.get(p):null;}return false;
    }
    private static boolean struck(JSONObject node,Map<String,JSONObject> nodes)throws Exception{
        JSONObject n=node;while(n!=null){if("del".equals(text(n,"tag"))||"s".equals(text(n,"tag")))return true;
            Object p=n.get("parent_path");n=p instanceof String?nodes.get(p):null;}return false;
    }
    private static boolean typeIs(JSONObject n,String type)throws Exception{
        String value=text(n,"item_type");return value.equals("https://schema.org/"+type)||value.equals("http://schema.org/"+type);
    }
    private static boolean prop(JSONObject n,String value)throws Exception{return Arrays.asList(text(n,"item_prop").split("\\s+")).contains(value);}
    private static boolean visible(JSONObject node,Map<String,JSONObject> nodes)throws Exception{
        JSONObject n=node;while(n!=null){
            if(!Boolean.TRUE.equals(n.get("visible_in_viewport"))||Boolean.TRUE.equals(n.get("hidden_attr"))
                    ||Boolean.TRUE.equals(n.get("inert_attr"))||"true".equals(text(n,"aria_hidden")))return false;
            Object p=n.get("parent_path");if(p==JSONObject.NULL)return "0".equals(text(n,"path"));n=nodes.get(p);
        }return false;
    }
    private static String join(List<String> strings){StringBuilder out=new StringBuilder();for(String s:strings)out.append(s).append('\n');return out.toString();}
    private static boolean descendant(String root,String path){return root.equals(path)||path.startsWith(root+"/");}
    private static String text(JSONObject value,String key)throws Exception{
        Object raw=value.get(key);need(raw instanceof String&&((String)raw).length()<=4096,"bounded actual DOM string: "+key);
        return (String)raw;
    }
    private static void need(boolean ok,String why){if(!ok)throw new IllegalArgumentException(why);}
}
