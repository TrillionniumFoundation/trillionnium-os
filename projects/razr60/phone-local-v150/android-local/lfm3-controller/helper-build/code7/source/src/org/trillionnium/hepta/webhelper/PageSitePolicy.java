package org.trillionnium.hepta.webhelper;

import org.json.JSONObject;
import org.trillionnium.hepta.local.web.WebShoppingGoal;
import org.trillionnium.hepta.webprotocol.WebEvidenceBinding;
import org.trillionnium.hepta.webprotocol.WebSitePolicy;
import org.trillionnium.hepta.webprotocol.WebTaskPurpose;

/** A single immutable policy per WebView. The original Csair predicate is unchanged. */
final class PageSitePolicy {
    final String kind,id,sha,initialUrl;
    private final WebSitePolicy shopping;
    private final JSONObject facts;
    private PageSitePolicy(String kind,String id,String initialUrl,JSONObject facts,WebSitePolicy shopping)throws Exception{
        this.kind=kind;this.id=id;this.initialUrl=initialUrl;this.facts=facts;this.shopping=shopping;
        sha=WebEvidenceBinding.sha256(facts);
        Jsons.need(shopping!=null||WebTaskPurpose.FLIGHT_KIND.equals(kind),"unsupported compiled page purpose");
        Jsons.need(origin(initialUrl)!=null,"initial page outside the one selected site");
    }
    static PageSitePolicy forTask(TaskBinding task)throws Exception{
        Jsons.need(task!=null,"task binding required");WebTaskPurpose p=task.purpose;
        PageSitePolicy policy=new PageSitePolicy(p.kind,p.sitePolicyId,p.initialUrl,p.policyEvidence(),
                p.shopping==null?null:WebSitePolicy.forShopping(p.shopping));
        Jsons.need(p.sitePolicySha256.equals(policy.sha),"compiled binding policy differs");return policy;
    }
    static PageSitePolicy diagnosticFlight()throws Exception{
        return new PageSitePolicy(WebTaskPurpose.FLIGHT_KIND,WebTaskPurpose.FLIGHT_POLICY_ID,
                WebTaskPurpose.FLIGHT_INITIAL_URL,WebTaskPurpose.flightPolicyEvidence(),null);
    }
    static PageSitePolicy diagnosticShopping()throws Exception{
        WebSitePolicy p=WebSitePolicy.forExplicitDiagnostic();
        return new PageSitePolicy(WebShoppingGoal.KIND,p.id,p.initialUrl,p.evidence(),p);
    }
    String origin(String raw){
        if(shopping==null)return OfficialOrigin.origin(raw);
        return shopping.allowsMainFrame(raw)?WebSitePolicy.ORIGIN:null;
    }
    boolean sameOrigin(String a,String b){
        if(shopping==null)return OfficialOrigin.sameOrigin(a,b);
        String left=origin(a);return left!=null&&left.equals(origin(b));
    }
    boolean allows(String raw){return origin(raw)!=null;}
    boolean shopping(){return shopping!=null;}
    boolean initial(String raw){return initialUrl.equals(raw);}
    boolean productDetail(String raw){return shopping!=null&&shopping.classify(raw)==WebSitePolicy.Route.PUBLIC_DETAIL_CANDIDATE;}
    JSONObject evidence()throws Exception{return new JSONObject(facts.toString());}
}
