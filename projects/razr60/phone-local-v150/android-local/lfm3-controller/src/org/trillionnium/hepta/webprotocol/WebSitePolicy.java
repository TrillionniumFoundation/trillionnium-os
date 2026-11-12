package org.trillionnium.hepta.webprotocol;

import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.local.web.WebShoppingGoal;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.regex.Pattern;

/**
 * One immutable mainland-Mi policy, selected only from a recognized shopping
 * contract. It is not appended to the existing Csair origin predicate.
 * It classifies public main-frame routes; DOM/native-action and product-result
 * proof are separate and cannot be obtained by matching a numeric URL.
 */
public final class WebSitePolicy {
    public static final String SCHEMA="hepta.web-site-policy.v1";
    public static final String ID="mi_cn_ax3000t_read_v1";
    public static final String ORIGIN="https://www.mi.com";
    public static final String INITIAL_URL=ORIGIN+"/shop/search?keyword=AX3000T";
    private static final Pattern DETAIL_QUERY=Pattern.compile("(?:cfrom=search&)?product_id=[1-9][0-9]{0,19}");
    public enum Route { INITIAL_PUBLIC_SEARCH, PUBLIC_DETAIL_CANDIDATE, DENIED }
    public final String id=ID,goalKind=WebShoppingGoal.KIND,initialUrl=INITIAL_URL,origin=ORIGIN,sha256;
    private final String immutableEvidence;
    private WebSitePolicy()throws Exception {
        JSONObject value=new JSONObject().put("schema",SCHEMA).put("site_policy_id",ID)
                .put("goal_kind",WebShoppingGoal.KIND).put("origin",ORIGIN).put("initial_url",INITIAL_URL)
                .put("route_policy","exact_search_or_numeric_public_detail_v1")
                .put("main_frame_only",true).put("regional_redirect_allowed",false)
                .put("external_app_launch_allowed",false).put("model_supplied_url_allowed",false)
                .put("model_supplied_javascript_allowed",false)
                .put("denied_navigation_categories",new JSONArray(Arrays.asList(
                    "account","login","cart","order","payment","coupon_claim","foreign_origin","regional_store")));
        immutableEvidence=WebEvidenceBinding.canonical(value);sha256=WebEvidenceBinding.sha256(value);
    }
    public static WebSitePolicy forShopping(WebShoppingGoal goal)throws Exception {
        if(goal==null)throw new IllegalArgumentException("recognized compiled shopping contract required");
        java.util.Map<String,Object> contract=goal.contract();
        if(!ID.equals(contract.get("site_policy_id"))||!WebShoppingGoal.KIND.equals(contract.get("kind"))
                ||!"AX3000T".equals(contract.get("model_term"))
                ||!WebShoppingGoal.contractHash(contract).equals(goal.contractSha256))
            throw new IllegalArgumentException("immutable shopping contract changed");
        return new WebSitePolicy();
    }
    /** Fixed display-0 manual diagnostic policy only; no OWNER or lease is fabricated. */
    public static WebSitePolicy forExplicitDiagnostic()throws Exception{return new WebSitePolicy();}
    public JSONObject evidence()throws Exception{return new JSONObject(immutableEvidence);}
    public boolean allowsMainFrame(String raw){return classify(raw)!=Route.DENIED;}
    public Route classify(String raw) {
        if(raw==null||raw.length()==0||raw.length()>4096)return Route.DENIED;
        try{
            URI uri=new URI(raw);
            if(uri.isOpaque()||!"https".equals(uri.getScheme())||!"www.mi.com".equals(uri.getRawAuthority())
                    ||!"www.mi.com".equals(uri.getHost())||uri.getRawUserInfo()!=null||uri.getPort()!=-1
                    ||uri.getRawFragment()!=null)return Route.DENIED;
            if(INITIAL_URL.equals(raw))return Route.INITIAL_PUBLIC_SEARCH;
            String query=uri.getRawQuery();
            if("/shop/buy/detail".equals(uri.getRawPath())&&query!=null&&DETAIL_QUERY.matcher(query).matches())
                return Route.PUBLIC_DETAIL_CANDIDATE;
        }catch(URISyntaxException invalid){return Route.DENIED;}
        return Route.DENIED;
    }
    /** Checks both recorded raw and browser-resolved href; it does not navigate. */
    public String observedProductLink(String committed,String hrefRaw,String hrefResolved,String target) {
        if(classify(committed)!=Route.INITIAL_PUBLIC_SEARCH||hrefRaw==null||hrefResolved==null
                ||hrefRaw.length()==0||hrefRaw.length()>4096
                ||!(target==null||target.length()==0||"_self".equals(target)))return null;
        try{
            URI raw=new URI(hrefRaw);String resolved=new URI(committed).resolve(raw).toString();
            if(!resolved.equals(hrefResolved)||classify(resolved)!=Route.PUBLIC_DETAIL_CANDIDATE)return null;
            return resolved;
        }catch(URISyntaxException invalid){return null;}
    }
    public String candidateProductId(String raw) {
        if(classify(raw)!=Route.PUBLIC_DETAIL_CANDIDATE)return null;
        try{String q=new URI(raw).getRawQuery();return q.substring(q.indexOf("product_id=")+"product_id=".length());}
        catch(URISyntaxException invalid){return null;}
    }
}
