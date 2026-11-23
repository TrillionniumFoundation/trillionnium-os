package org.trillionnium.hepta.webprotocol;

import java.util.Arrays;
import java.util.Collections;
import java.util.Set;
import java.util.TreeSet;
import org.json.JSONArray;
import org.json.JSONObject;
import org.trillionnium.hepta.local.TaskAuthorization;
import org.trillionnium.hepta.local.web.WebFlightGoal;
import org.trillionnium.hepta.local.web.WebShoppingGoal;

/**
 * One complete original OWNER selects one compiled public-page purpose.
 * The actual TaskAuthorization compiler runs on that same original text.
 * This supplies a maximum page scope, never a replacement instruction or URL parameter.
 */
public final class WebTaskPurpose {
    public static final String FLIGHT_KIND="csair_public_flight";
    public static final String FLIGHT_POLICY_ID="csair_public_flight_v1";
    public static final String FLIGHT_INITIAL_URL="https://m.csair.com/";
    public static final String ORIGINAL_CSAIR_POLICY_SHA256="7a127a62aa8918be1224b886f90f939bf31146a6522dd2f8a0af0244a57749eb";
    public static final Set<String> BINDING_KEYS=Collections.unmodifiableSet(new TreeSet<String>(Arrays.asList(
            "schema","initial_url","goal_kind","site_policy_id","site_policy_sha256","task_id",
            "controller_session_nonce","owner","owner_sha256","contract_sha256","authorization",
            "background","controller_identity","helper_identity","storage_profile_name")));
    public final String owner,ownerSha256,contractSha256,kind,sitePolicyId,sitePolicySha256,initialUrl;
    public final boolean naturalReadOnlyIntent;
    public final WebFlightGoal flight;
    public final WebShoppingGoal shopping;
    public final TaskAuthorization authorization;
    private final JSONObject policy;

    private WebTaskPurpose(String original,WebFlightGoal flight,WebShoppingGoal shopping)throws Exception{
        this.owner=original;this.flight=flight;this.shopping=shopping;
        authorization=TaskAuthorization.parse(original);
        authorization.requireOwner(original);
        require(authorization.allows("open")&&!authorization.requireFindAppBeforeOpen,
                "original OWNER does not allow the selected helper bootstrap");
        if(shopping!=null){
            require(shopping.allowsInitialOfficialPage(),"shopping initial page not supported");
            ownerSha256=shopping.ownerSha256;contractSha256=shopping.contractSha256;
            kind=WebShoppingGoal.KIND;sitePolicyId=WebShoppingGoal.SITE_POLICY_ID;
            initialUrl=WebSitePolicy.INITIAL_URL;naturalReadOnlyIntent=shopping.naturalReadOnlyIntent;
            policy=WebSitePolicy.forShopping(shopping).evidence();
            require(shopping.toolCeiling().containsAll(authorization.allowedTools),"shopping tool ceiling differs");
        }else{
            require(flight!=null&&flight.allowsInitialOfficialPage(),"background flight initial page not supported");
            ownerSha256=flight.ownerSha256;contractSha256=flight.contractSha256;
            kind=FLIGHT_KIND;sitePolicyId=FLIGHT_POLICY_ID;initialUrl=FLIGHT_INITIAL_URL;
            naturalReadOnlyIntent=flight.naturalReadOnlyIntent;
            require(flight.toolCeiling().containsAll(authorization.allowedTools),"flight tool ceiling differs");
            policy=flightPolicyEvidence();
        }
        require(ownerSha256.equals(authorization.instructionSha256),"original OWNER/compiler hash differs");
        sitePolicySha256=WebEvidenceBinding.sha256(policy);
    }
    /** Compiled policy data; this neither constructs an OWNER nor grants a task. */
    public static JSONObject flightPolicyEvidence()throws Exception{
        return new JSONObject().put("schema","hepta.web-site-policy.v1").put("site_policy_id",FLIGHT_POLICY_ID)
                .put("goal_kind",FLIGHT_KIND).put("initial_url",FLIGHT_INITIAL_URL)
                .put("main_frame_origins",new JSONArray(Arrays.asList("https://b2c.csair.com","https://m.csair.com")))
                .put("navigation_policy","existing_csair_official_origin_only")
                .put("original_origin_source_sha256",ORIGINAL_CSAIR_POLICY_SHA256)
                .put("arbitrary_url_input",false).put("arbitrary_javascript_input",false)
                .put("grants_page_action",false).put("business_verified",false);
    }
    public static WebTaskPurpose fromOwner(String original)throws Exception{
        WebFlightGoal flight=WebFlightGoal.parse(original);
        WebShoppingGoal shopping=WebShoppingGoal.parse(original);
        require((flight==null)!=(shopping==null),"exactly one supported original public-page goal required");
        return new WebTaskPurpose(original,flight,shopping);
    }
    public static WebTaskPurpose fromAttach(JSONObject attach)throws Exception{
        WebTaskPurpose purpose=fromOwner(text(attach,"owner"));
        require(purpose.ownerSha256.equals(text(attach,"owner_sha256"))
                &&purpose.contractSha256.equals(text(attach,"contract_sha256")),"original goal hash differs");
        JSONObject actualAuthorization=new JSONObject(purpose.authorization.evidence());
        require(WebEvidenceBinding.canonical(actualAuthorization).equals(
                WebEvidenceBinding.canonical(attach.getJSONObject("authorization"))),
                "actual original OWNER compiler evidence differs");
        return purpose;
    }
    public static WebTaskPurpose requireBinding(JSONObject binding)throws Exception{
        Set<String> keys=new TreeSet<String>();java.util.Iterator<String> it=binding.keys();while(it.hasNext())keys.add(it.next());
        require(keys.equals(BINDING_KEYS)&&WebEvidenceProtocol.BINDING_SCHEMA.equals(text(binding,"schema")),
                "current immutable binding shape differs");
        WebTaskPurpose purpose=fromAttach(binding);
        require(purpose.kind.equals(text(binding,"goal_kind"))
                &&purpose.sitePolicyId.equals(text(binding,"site_policy_id"))
                &&purpose.sitePolicySha256.equals(text(binding,"site_policy_sha256"))
                &&purpose.initialUrl.equals(text(binding,"initial_url")),"compiled single-site purpose differs");
        require(WebStorageEvidence.profileFor(text(binding,"controller_session_nonce"))
                .equals(text(binding,"storage_profile_name")),"lease storage profile differs");
        return purpose;
    }
    public JSONObject policyEvidence()throws Exception{return new JSONObject(WebEvidenceBinding.canonical(policy));}
    private static String text(JSONObject value,String key)throws Exception{
        Object raw=value.get(key);require(raw instanceof String,"string "+key+" required");return (String)raw;
    }
    private static void require(boolean yes,String reason){if(!yes)throw new IllegalArgumentException(reason);}
}
