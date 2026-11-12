package org.trillionnium.hepta.local.web;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pure-Java bounded original-user intent for one official public product lookup.
 * No JSON, Android or Binder dependency is introduced into TaskAuthorization.
 * Recognition derives an immutable data contract, never rewrites OWNER and never
 * grants a tool. Original authority and current single-helper selection are
 * separate, mandatory controller/helper gates.
 */
public final class WebShoppingGoal {
    public static final String SCHEMA="hepta.web-shopping-goal.v1";
    public static final String KIND="mi_public_product";
    public static final String SITE_POLICY_ID="mi_cn_ax3000t_read_v1";
    public static final String MODEL_TERM="AX3000T";
    public static final String DISPLAY_MODEL="Xiaomi 路由器 AX3000T";
    public static final String LEGACY_EXPLICIT_OWNER=
            "在小米中国官方商城只读查询 Xiaomi 路由器 AX3000T 的单件配置，核对 Wi-Fi 6、3000M级、4个自适应WAN/LAN口，告诉我该配置当前公开的人民币价格，以及是否为起价、划线对比价、券后价或附带条件。不登录、不领券、不加购物车、不下单、不付款。";
    public static final Set<String> TOOL_CEILING=Collections.unmodifiableSet(
            new TreeSet<String>(Arrays.asList("open","click","back","scroll","wait","done")));
    private static final Pattern MODEL_FIRST=Pattern.compile(
            "^(?:请)?(?:帮我)?(?:查一下|查下|查询|查查|查看)(?:小米|Xiaomi)[ ]?(?:路由器[ ]?)?"
            +"(AX3000T)(?:的)?(?:官网|官方商城|中国官方商城)(?:售价|价格)[。？?]?$",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern STORE_FIRST=Pattern.compile(
            "^(?:请)?(?:帮我)?(?:查一下|查下|查询|查查|查看)(?:小米|Xiaomi)(?:中国)?(?:官网|官方商城)"
            +"[ ]?(?:路由器[ ]?)?(AX3000T)(?:的)?(?:售价|价格)[。？?]?$",
            Pattern.CASE_INSENSITIVE);
    private static final Set<String> FORBIDDEN=Collections.unmodifiableSet(new TreeSet<String>(
            Arrays.asList("login","register","consent_grant","coupon_claim","cart","order","payment",
                    "account_change","permission_change","arbitrary_app","arbitrary_url","arbitrary_js")));
    public final String owner,ownerSha256,contractSha256;
    public final String contractSchema=SCHEMA,providerSelection=KIND,recognition;
    public final int productStartUtf16,productEndUtf16;
    public final boolean naturalReadOnlyIntent,specificationsRequested,singleUnitRequested;
    private final Map<String,Object> immutableContract;
    private final String canonicalContract;

    private WebShoppingGoal(String raw,int start,int end,boolean natural) {
        owner=raw;ownerSha256=hash(raw);productStartUtf16=start;productEndUtf16=end;
        naturalReadOnlyIntent=natural;specificationsRequested=!natural;singleUnitRequested=!natural;
        recognition=natural?"bounded_natural_official_product_price.v1":"legacy_complete_explicit_product_read.v1";
        Map<String,Object> c=new LinkedHashMap<String,Object>();
        c.put("schema",SCHEMA);c.put("kind",KIND);c.put("owner_sha256",ownerSha256);
        c.put("owner_span_utf16",list(Integer.valueOf(0),Integer.valueOf(raw.length())));
        c.put("model_span_utf16",list(Integer.valueOf(start),Integer.valueOf(end)));c.put("model_term",MODEL_TERM);
        c.put("site_policy_id",SITE_POLICY_ID);c.put("market","mainland_china");
        c.put("purpose","public_product_price_information");c.put("natural_language_intent",Boolean.valueOf(natural));
        c.put("single_unit_requested",Boolean.valueOf(singleUnitRequested));
        c.put("specifications_requested",Boolean.valueOf(specificationsRequested));
        c.put("required_specifications",specificationsRequested?list("Wi-Fi 6","3000M级","4个自适应WAN/LAN口"):list());
        c.put("tool_ceiling",Collections.unmodifiableList(new ArrayList<String>(TOOL_CEILING)));
        c.put("forbidden_operations",Collections.unmodifiableList(new ArrayList<String>(FORBIDDEN)));
        c.put("preserve_price_conditions",Boolean.TRUE);c.put("visible_currency_required",Boolean.TRUE);
        c.put("same_product_context_required",Boolean.TRUE);c.put("navigation_from_observed_link_required",Boolean.TRUE);
        c.put("exact_variant_not_inferred",Boolean.TRUE);c.put("search_card_is_not_detail_result",Boolean.TRUE);
        immutableContract=Collections.unmodifiableMap(c);canonicalContract=canonical(c);contractSha256=hash(canonicalContract);
    }
    public static WebShoppingGoal parse(String raw) {
        if(!valid(raw))return null;
        if(LEGACY_EXPLICIT_OWNER.equals(raw)){
            int start=raw.indexOf(MODEL_TERM);return new WebShoppingGoal(raw,start,start+MODEL_TERM.length(),false);
        }
        Matcher match=MODEL_FIRST.matcher(raw);
        if(!match.matches()){match=STORE_FIRST.matcher(raw);if(!match.matches())return null;}
        return new WebShoppingGoal(raw,match.start(1),match.end(1),true);
    }
    /**
     * Lets the UI refuse/clarify an unsupported shopping-like OWNER instead of
     * silently falling back to generic application operation.
     * A true result is never authority and is not a successful parse.
     */
    public static boolean resemblesSupportedIntent(String raw) {
        if(!valid(raw))return false;
        return Pattern.compile("AX3000T",Pattern.CASE_INSENSITIVE).matcher(raw).find()
                &&(raw.contains("小米")||Pattern.compile("Xiaomi",Pattern.CASE_INSENSITIVE).matcher(raw).find())
                &&(raw.contains("官网")||raw.contains("官方商城"))
                &&(raw.contains("价")||raw.contains("购买")||raw.contains("下单"));
    }
    /** Intent only; original authority, current UI selection and lease are still required. */
    public boolean allowsInitialOfficialPage(){return true;}
    public Set<String> toolCeiling(){return TOOL_CEILING;}
    public Map<String,Object> contract(){return immutableContract;}
    public String canonicalContract(){return canonicalContract;}
    public static String contractHash(Map<String,Object> value){return hash(canonical(value));}
    public Map<String,Object> evidence() {
        Map<String,Object> observed=new LinkedHashMap<String,Object>();
        for(String key:Arrays.asList("product_id","selected_variant","quantity","price_raw","amount_decimal","currency","price_kind","committed_url"))
            observed.put(key,null);
        observed.put("product_result_verified",Boolean.FALSE);
        Map<String,Object> out=new LinkedHashMap<String,Object>();
        out.put("schema",SCHEMA);out.put("kind",KIND);out.put("original_owner",owner);
        out.put("owner_sha256",ownerSha256);out.put("contract_sha256",contractSha256);out.put("contract",immutableContract);
        out.put("recognition",recognition);out.put("observed",Collections.unmodifiableMap(observed));
        out.put("original_owner_rewritten",Boolean.FALSE);out.put("task_authorization_compiled",Boolean.FALSE);
        out.put("grants_tool_authority",Boolean.FALSE);out.put("query_executed",Boolean.FALSE);out.put("business_verified",Boolean.FALSE);
        return Collections.unmodifiableMap(out);
    }
    private static List<Object> list(Object... values){return Collections.unmodifiableList(Arrays.asList(values));}
    private static boolean valid(String raw) {
        if(raw==null||raw.length()==0||raw.getBytes(StandardCharsets.UTF_8).length>1600)return false;
        for(int i=0;i<raw.length();i++){
            char c=raw.charAt(i);
            if(Character.isHighSurrogate(c)){if(++i>=raw.length()||!Character.isLowSurrogate(raw.charAt(i)))return false;}
            else if(Character.isLowSurrogate(c)||Character.isISOControl(c))return false;
        }
        return true;
    }
    /** Canonical JSON data encoding: UTF16-sorted object keys, ordered arrays, no floats. */
    private static String canonical(Object value) {
        if(value==null)return "null";
        if(value instanceof Boolean||value instanceof Integer||value instanceof Long)return value.toString();
        if(value instanceof String){
            String s=(String)value;StringBuilder out=new StringBuilder("\"");
            for(int i=0;i<s.length();i++){
                char c=s.charAt(i);
                if(Character.isHighSurrogate(c)){
                    if(i+1>=s.length()||!Character.isLowSurrogate(s.charAt(i+1)))throw new IllegalArgumentException("invalid Unicode");
                    out.append(c).append(s.charAt(++i));continue;
                }
                if(Character.isLowSurrogate(c))throw new IllegalArgumentException("invalid Unicode");
                if(c=='\"'||c=='\\')out.append('\\').append(c);
                else if(c<0x20){String h=Integer.toHexString(c);out.append("\\u");for(int n=h.length();n<4;n++)out.append('0');out.append(h);}
                else out.append(c);
            }
            return out.append('\"').toString();
        }
        if(value instanceof List){
            StringBuilder out=new StringBuilder("[");List<?> a=(List<?>)value;
            for(int i=0;i<a.size();i++){if(i>0)out.append(',');out.append(canonical(a.get(i)));}return out.append(']').toString();
        }
        if(value instanceof Map){
            Map<?,?> map=(Map<?,?>)value;TreeSet<String> keys=new TreeSet<String>();
            for(Object key:map.keySet()){if(!(key instanceof String))throw new IllegalArgumentException("string map key required");keys.add((String)key);}
            StringBuilder out=new StringBuilder("{");int index=0;
            for(String key:keys){if(index++>0)out.append(',');out.append(canonical(key)).append(':').append(canonical(map.get(key)));}
            return out.append('}').toString();
        }
        throw new IllegalArgumentException("noncanonical contract type");
    }
    private static String hash(String raw) {
        try{
            byte[] bytes=MessageDigest.getInstance("SHA-256").digest(raw.getBytes(StandardCharsets.UTF_8));
            StringBuilder out=new StringBuilder(64);char[] hex="0123456789abcdef".toCharArray();
            for(byte b:bytes)out.append(hex[(b>>>4)&15]).append(hex[b&15]);return out.toString();
        }catch(NoSuchAlgorithmException impossible){throw new IllegalStateException("SHA-256 unavailable",impossible);}
    }
}
