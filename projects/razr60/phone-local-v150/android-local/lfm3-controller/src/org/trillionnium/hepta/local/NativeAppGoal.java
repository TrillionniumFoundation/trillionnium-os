package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.DateTimeException;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Literal OWNER data for an explicitly selected native App. This is recognition,
 * not a provider, tool grant, UI selector, installed-identity proof or result.
 * A task must retain this same immutable object through selection and completion.
 */
public final class NativeAppGoal {
    public static final String SCHEMA = "hepta.native-app-owner.v1";
    public static final String PRODUCT_PRICE = "native_product_price";
    public static final String PRODUCT_ORDER_PREVIEW = "native_product_order_preview";
    public static final String FLIGHT_RESULTS = "native_flight_results";
    public static final String CTRIP_PACKAGE = "ctrip.android.view";
    public static final String CSAIR_PACKAGE = "com.csair.mbp";
    public static final String XIAOMI_PACKAGE = "com.xiaomi.shop";
    public static final String PRODUCT_MODEL = "AX3000T";

    private static final Set<String> QUERY_TOOLS = Collections.unmodifiableSet(new TreeSet<String>(
            Arrays.asList("open", "click", "type", "submit", "scroll", "back", "wait", "done")));
    private static final String READ_ACTUAL_FLIGHT_FORM = "complete_literal_native_flight_read_only_no_order.v1";
    private static final Set<String> READ_ACTUAL_FLIGHT_TOOLS = Collections.unmodifiableSet(new TreeSet<String>(
            Arrays.asList("open", "click", "type", "scroll", "back", "wait", "done")));
    private static final Set<String> PREVIEW_READ_TOOLS = Collections.unmodifiableSet(new TreeSet<String>(
            Arrays.asList("open","click","type","back","wait","done")));
    private static final String PREFIX = "(?:请)?(?:帮我)?";
    private static final String APP = "(?:(?:在|用)(携程旅行|携程|中国南方航空|南航)"
            + "(?:APP|App|app|应用)?(?:里|中|上)?)?";
    private static final String QUERY = "(?:查一下|查下|查询|查查)";
    private static final String ROUTE = "(?:从)?([\\p{IsHan}]{2,12}?)到([\\p{IsHan}]{2,12}?)"
            + "(?:的)?单程(?:机票|航班)[，,](?:1|一)(?:名|位)成人[。]?";
    private static final Pattern FLIGHT_ZH = Pattern.compile(PREFIX + APP + QUERY
            + "([0-9]{4})年([0-9]{1,2})月([0-9]{1,2})日" + ROUTE);
    private static final Pattern FLIGHT_ISO = Pattern.compile(PREFIX + APP + QUERY
            + "([0-9]{4})-([0-9]{2})-([0-9]{2})" + ROUTE);
    // Recognize ASCII spaces only between complete literal fields. Match the
    // original OWNER directly: do not trim, join city/date characters, rewrite
    // offsets, infer parameters or change the existing query-only tool ceiling.
    private static final String FIELD_SPACE = "[ ]*";
    private static final String SPACED_ROUTE = "(?:从" + FIELD_SPACE + ")?([\\p{IsHan}]{2,12}?)"
            + FIELD_SPACE + "到" + FIELD_SPACE + "([\\p{IsHan}]{2,12}?)" + FIELD_SPACE
            + "(?:的" + FIELD_SPACE + ")?单程" + FIELD_SPACE + "(?:机票|航班)" + FIELD_SPACE
            + "[，,]" + FIELD_SPACE + "(?:1|一)" + FIELD_SPACE + "(?:名|位)" + FIELD_SPACE + "成人[。]?";
    private static final Pattern FLIGHT_ZH_SPACED = Pattern.compile(PREFIX + APP + QUERY + FIELD_SPACE
            + "([0-9]{4})年([0-9]{1,2})月([0-9]{1,2})日" + FIELD_SPACE + SPACED_ROUTE);
    private static final Pattern FLIGHT_ISO_SPACED = Pattern.compile(PREFIX + APP + QUERY + FIELD_SPACE
            + "([0-9]{4})-([0-9]{2})-([0-9]{2})" + FIELD_SPACE + SPACED_ROUTE);
    private static final Pattern PRODUCT = Pattern.compile(PREFIX
            + "(?:(?:在|用)小米商城(?:APP|App|app|应用)?(?:里|中|上)?)?"
            + "(?:查一下|查下|查询|查查|查看)(?:小米|Xiaomi)[ ]?(?:路由器[ ]?)?"
            + "(AX3000T)(?:的)?(?:售价|价格)[。？?]?", Pattern.CASE_INSENSITIVE);
    private static final Pattern PRODUCT_IN_APP = Pattern.compile(PREFIX
            + "(?:在|用)小米商城(?:APP|App|app|应用)?(?:里|中|上)?"
            + "(?:查一下|查下|查询|查查|查看)(?:路由器[ ]?)?"
            + "(AX3000T)(?:的)?(?:售价|价格)[。？?]?", Pattern.CASE_INSENSITIVE);
    // These are complete additional OWNER forms, not suffix stripping. Every
    // report field and query-only limit must be present, and no remainder is
    // accepted. Recognition still does not claim a provider or grant a tool.
    private static final String READ_FLIGHT_ROUTE = "(?:从" + FIELD_SPACE + ")?([\\p{IsHan}]{2,12}?)"
            + FIELD_SPACE + "到" + FIELD_SPACE + "([\\p{IsHan}]{2,12}?)" + FIELD_SPACE
            + "(?:的" + FIELD_SPACE + ")?单程" + FIELD_SPACE + "(?:机票|航班)" + FIELD_SPACE
            + "[，,]" + FIELD_SPACE + "(?:1|一)" + FIELD_SPACE + "(?:名|位)" + FIELD_SPACE + "成人"
            + "[，,]" + FIELD_SPACE + "读取航班列表中可见的航班时间[、，,]航司和价格[。.]"
            + FIELD_SPACE + "只查询[，,]不预订[、，,]不支付[。.]?";
    private static final Pattern READ_FLIGHT_ZH = Pattern.compile(PREFIX + APP + QUERY + FIELD_SPACE
            + "([0-9]{4})年([0-9]{1,2})月([0-9]{1,2})日" + FIELD_SPACE + READ_FLIGHT_ROUTE);
    private static final Pattern READ_FLIGHT_ISO = Pattern.compile(PREFIX + APP + QUERY + FIELD_SPACE
            + "([0-9]{4})-([0-9]{2})-([0-9]{2})" + FIELD_SPACE + READ_FLIGHT_ROUTE);
    // A complete additional Ctrip OWNER form. Its explicit no-order clause
    // narrows the original tool mask; generic submit is unnecessary for the
    // observed flight query button, which remains an independently guarded click.
    private static final String READ_ACTUAL_FLIGHT_ROUTE = "(?:从" + FIELD_SPACE + ")?([\\p{IsHan}]{2,12}?)"
            + FIELD_SPACE + "到" + FIELD_SPACE + "([\\p{IsHan}]{2,12}?)" + FIELD_SPACE
            + "(?:的" + FIELD_SPACE + ")?单程" + FIELD_SPACE + "(?:机票|航班)" + FIELD_SPACE
            + "[，,]" + FIELD_SPACE + "(?:1|一)" + FIELD_SPACE + "(?:名|位)" + FIELD_SPACE + "成人"
            + "[，,]" + FIELD_SPACE + "读取真实航班和票价[。.]"
            + FIELD_SPACE + "只查询[，,]不预订[、，,]不提交订单[、，,]不支付[。.]?";
    private static final Pattern READ_ACTUAL_FLIGHT_ZH = Pattern.compile(PREFIX + APP + QUERY + FIELD_SPACE
            + "([0-9]{4})年([0-9]{1,2})月([0-9]{1,2})日" + FIELD_SPACE + READ_ACTUAL_FLIGHT_ROUTE);
    private static final Pattern READ_ACTUAL_FLIGHT_ISO = Pattern.compile(PREFIX + APP + QUERY + FIELD_SPACE
            + "([0-9]{4})-([0-9]{2})-([0-9]{2})" + FIELD_SPACE + READ_ACTUAL_FLIGHT_ROUTE);
    private static final Pattern READ_PRODUCT = Pattern.compile(PREFIX
            + "(?:在|用)小米商城(?:APP|App|app|应用)?(?:里|中|上)?"
            + "(?:搜索|查询|查找)(?:小米|Xiaomi)[ ]?(?:路由器[ ]?)?([A-Za-z][A-Za-z0-9-]{1,31})"
            + "[，,]" + FIELD_SPACE + "读取实际商品页面显示的当前(?:售价|价格)并说明商品型号[。.]"
            + FIELD_SPACE + "只查询[，,]不购买[、，,]不提交订单[、，,]不支付[。.]?", Pattern.CASE_INSENSITIVE);
    private static final String SHOP = PREFIX+"在小米商城(?:APP|App|app|应用)?(?:里|中|上)?";
    private static final String ITEM = "(?:小米|Xiaomi)?(?:路由器)?[ ]*(?<model>AX3000T)(?:[ ]*[(（](?<variant>白色|标准版)[)）])?";
    private static final String UNIT = "(?<units>1|一)[ ]*(?:台|件)";
    private static final String CAP = "(?:人民币)?[ ]*(?<cap>[1-9][0-9]{0,5}(?:\\.[0-9]{1,2})?)[ ]*元";
    private static final String NO_TRANSACTION = "[，,。.]?[ ]*不提交(?:订单)?[、，,][ ]*不(?:支付|付款)[。.]?";
    private static final Pattern PREVIEW_BUY = Pattern.compile(SHOP+"(?:买|准备购买)"+UNIT+ITEM
            +"[，,]预算(?:不超过|上限为)"+CAP+"[，,]核对商品[、，,]数量和总额后停在订单确认页"+NO_TRANSACTION,Pattern.CASE_INSENSITIVE);
    private static final Pattern PREVIEW_PRICE = Pattern.compile(SHOP+"(?:给|为)?"+ITEM+"[，, ]*"+UNIT
            +"[，,][ ]*核价[，,][ ]*预算(?:不超过|上限为)?"+CAP
            +"[，,][ ]*若(?:金额|总额)在预算内(?:就)?(?:准备到|到)(?:订单)?确认页停下"+NO_TRANSACTION,Pattern.CASE_INSENSITIVE);

    // An explicit, finite fixture owner. This is not a suffix added to a query owner.
    private static final Pattern MANUAL_PREVIEW_FIXTURE = Pattern.compile("测试采集订单预览\\[(?<manualPurpose>preview_open_sku|preview_select_requested_variant|preview_open_confirmation)\\]："+SHOP+"准备购买"+UNIT+ITEM
            +"[，,]预算不超过"+CAP+"[，,]核对商品、数量和总额后停在订单确认页"+NO_TRANSACTION);

    /** Owner values only. No observed stock, selected SKU, order total, or action follows from recognition. */
    public static final class OrderPreview {
        public final String capYuan, requestedVariant;
        public final int quantity,quantityStartUtf16,quantityEndUtf16,capStartUtf16,capEndUtf16;
        private OrderPreview(Matcher match){
            capYuan=match.group("cap");requestedVariant=match.group("variant");quantity=1;
            quantityStartUtf16=match.start("units");quantityEndUtf16=match.end("units");
            capStartUtf16=match.start("cap");capEndUtf16=match.end("cap");
        }
        static String describe(String amount,String cap,String variant){
            int comparison=new java.math.BigDecimal(amount).compareTo(new java.math.BigDecimal(cap));
            String requested=variant==null?"":("，指定款式"+variant);
            return "小米商城的 AX3000T 商品详情页显示 "+amount+" 元。您要求 1 件"+requested
                    +"，预算 "+cap+" 元。页面展示单价"+(comparison>0?"高于":comparison<0?"低于":"等于")
                    +"预算。尚未核实所选款式、数量及结算总额，已停在商品详情页。";
        }
        Map<String,Object> evidence(){
            Map<String,Object> budget=new LinkedHashMap<String,Object>();budget.put("quantity",quantity);
            budget.put("budget_ceiling_yuan",capYuan);budget.put("requested_variant",requestedVariant);
            budget.put("quantity_start_utf16",quantityStartUtf16);budget.put("quantity_end_utf16",quantityEndUtf16);
            budget.put("budget_start_utf16",capStartUtf16);budget.put("budget_end_utf16",capEndUtf16);
            budget.put("stop_at_order_confirmation",true);budget.put("order_submission_authorized",false);
            budget.put("payment_authorized",false);return Collections.unmodifiableMap(budget);
        }
    }
    public final OrderPreview orderPreview;
    public boolean readsXiaomiProduct(){
        return XIAOMI_PACKAGE.equals(packageName)&&(PRODUCT_PRICE.equals(kind)||PRODUCT_ORDER_PREVIEW.equals(kind)&&orderPreview!=null);
    }
    private static final Pattern CITY_CONTROL = Pattern.compile(
            ".*(?:或者|以及|然后|打开|查询|搜索|预订|下单|支付|删除|提醒|闹钟|成人|儿童|婴儿|登录|注册|授权|机票|航班|官网|网页|商城).*");

    public final String kind, packageName, immutableOwner, ownerSha256, contractSha256, recognition;
    public final Set<String> toolCeiling;
    /** Literal requested facts. Fields of the other kind are null/-1, never inferred. */
    public final String fromCity, toCity, productModel;
    public final LocalDate departureDate;
    public final int adults, children, infants;
    public final int dateStartUtf16, dateEndUtf16, fromStartUtf16, fromEndUtf16, toStartUtf16, toEndUtf16;
    public final int modelStartUtf16, modelEndUtf16;

    private NativeAppGoal(String owner, String selectedPackage, Matcher match, LocalDate date, int suffix) {
        this(owner, selectedPackage, match, date, suffix, "complete_literal_native_single_adult_flight.v1");
    }

    private NativeAppGoal(String owner, String selectedPackage, Matcher match, LocalDate date, int suffix, String form) {
        kind = FLIGHT_RESULTS; orderPreview=null; packageName = selectedPackage; immutableOwner = owner; ownerSha256 = hash(owner);
        recognition = form;
        toolCeiling = READ_ACTUAL_FLIGHT_FORM.equals(form) ? READ_ACTUAL_FLIGHT_TOOLS : QUERY_TOOLS;
        departureDate = date; fromCity = match.group(5); toCity = match.group(6); productModel = null;
        adults = 1; children = 0; infants = 0;
        dateStartUtf16 = match.start(2); dateEndUtf16 = match.end(4) + suffix;
        fromStartUtf16 = match.start(5); fromEndUtf16 = match.end(5);
        toStartUtf16 = match.start(6); toEndUtf16 = match.end(6);
        modelStartUtf16 = modelEndUtf16 = -1;
        contractSha256 = contractHash();
    }

    private NativeAppGoal(String owner, String selectedPackage, Matcher match) {
        this(owner, selectedPackage, match, "complete_literal_native_ax3000t_price.v1");
    }

    private NativeAppGoal(String owner, String selectedPackage, Matcher match, String form) {
        this(owner,selectedPackage,match,form,null);
    }
    private NativeAppGoal(String owner,String selectedPackage,Matcher match,String form,OrderPreview preview) {
        orderPreview=preview;kind = preview==null?PRODUCT_PRICE:PRODUCT_ORDER_PREVIEW; packageName = selectedPackage; immutableOwner = owner; ownerSha256 = hash(owner);
        recognition = form; toolCeiling = preview==null?QUERY_TOOLS:PREVIEW_READ_TOOLS;
        departureDate = null; fromCity = toCity = null; productModel = PRODUCT_MODEL;
        adults = children = infants = -1;
        dateStartUtf16 = dateEndUtf16 = fromStartUtf16 = fromEndUtf16 = toStartUtf16 = toEndUtf16 = -1;
        modelStartUtf16 = preview==null?match.start(1):match.start("model");
        modelEndUtf16 = preview==null?match.end(1):match.end("model");
        contractSha256 = contractHash();
    }

    /** Unsupported/incomplete/mismatched OWNER or unrecognized selected package -> null.
     * No trim, suffix removal, app substitution, website fallback or inferred date.
     * The package list identifies recognized purposes only; installed identity and
     * each App's real, current observation provider must be checked separately.
     */
    public static NativeAppGoal parse(String owner, String explicitlySelectedPackage) {
        if (!valid(owner) || explicitlySelectedPackage == null) return null;
        if (CTRIP_PACKAGE.equals(explicitlySelectedPackage) || CSAIR_PACKAGE.equals(explicitlySelectedPackage)) {
            String form = "complete_literal_native_single_adult_flight.v1";
            Matcher match = FLIGHT_ZH.matcher(owner); int suffix = 1;
            if (!match.matches()) {
                match = FLIGHT_ISO.matcher(owner); suffix = 0;
                if (!match.matches()) {
                    match = FLIGHT_ZH_SPACED.matcher(owner); suffix = 1;
                    if (!match.matches()) {
                        match = FLIGHT_ISO_SPACED.matcher(owner); suffix = 0;
                        if (!match.matches()) {
                            form = "complete_literal_native_flight_read_only_report.v2";
                            match = READ_FLIGHT_ZH.matcher(owner); suffix = 1;
                            if (!match.matches()) {
                                match = READ_FLIGHT_ISO.matcher(owner); suffix = 0;
                                if (!match.matches()) {
                                    if (!CTRIP_PACKAGE.equals(explicitlySelectedPackage)) return null;
                                    match = READ_ACTUAL_FLIGHT_ZH.matcher(owner); suffix = 1;
                                    if (!match.matches()) {
                                        match = READ_ACTUAL_FLIGHT_ISO.matcher(owner); suffix = 0;
                                        if (!match.matches()) return null;
                                    }
                                    form = READ_ACTUAL_FLIGHT_FORM;
                                }
                            }
                        }
                    }
                }
            }
            String namedApp = match.group(1);
            if (namedApp != null && !explicitlySelectedPackage.equals(packageForName(namedApp))) return null;
            if (!singleCity(match.group(5)) || !singleCity(match.group(6))
                    || match.group(5).equals(match.group(6))) return null;
            try {
                LocalDate date = LocalDate.of(Integer.parseInt(match.group(2)),
                        Integer.parseInt(match.group(3)), Integer.parseInt(match.group(4)));
                if (date.getYear() < 1) return null;
                return new NativeAppGoal(owner, explicitlySelectedPackage, match, date, suffix, form);
            } catch (DateTimeException | NumberFormatException invalid) {
                return null;
            }
        }
        if (XIAOMI_PACKAGE.equals(explicitlySelectedPackage)) {
            Matcher manual=MANUAL_PREVIEW_FIXTURE.matcher(owner);
            if(manual.matches())return new NativeAppGoal(owner,explicitlySelectedPackage,manual,
                    "complete_literal_manual_order_preview_fixture.v1/"+manual.group("manualPurpose"),new OrderPreview(manual));
            Matcher preview=PREVIEW_BUY.matcher(owner);
            if(!preview.matches())preview=PREVIEW_PRICE.matcher(owner);
            if(preview.matches())return new NativeAppGoal(owner,explicitlySelectedPackage,preview,
                    "complete_literal_one_unit_budgeted_order_preview.v1",new OrderPreview(preview));
            Matcher match = PRODUCT.matcher(owner);
            if (!match.matches()) {
                match = PRODUCT_IN_APP.matcher(owner);
                if (!match.matches()) {
                    match = READ_PRODUCT.matcher(owner);
                    // Preserve the existing qualified product boundary. An
                    // unsupported literal model must never be substituted.
                    if (!match.matches() || !PRODUCT_MODEL.equalsIgnoreCase(match.group(1))) return null;
                    return new NativeAppGoal(owner, explicitlySelectedPackage, match,
                            "complete_literal_native_product_read_only_report.v2");
                }
            }
            return new NativeAppGoal(owner, explicitlySelectedPackage, match);
        }
        return null;
    }

    /** Same complete original OWNER and exact explicit package, never model text. */
    public void requireBinding(String owner, String selectedPackage) {
        if (!valid(owner) || !immutableOwner.equals(owner) || !ownerSha256.equals(hash(owner))
                || !packageName.equals(selectedPackage))
            throw new IllegalArgumentException("native goal differs from immutable owner or selected package");
    }

    public boolean departureNotBefore(LocalDate actualTaskLocalDate) {
        return FLIGHT_RESULTS.equals(kind) && actualTaskLocalDate != null
                && !departureDate.isBefore(actualTaskLocalDate);
    }

    /** Fresh detached map; every asserted value is an OWNER fact, never observed output. */
    public Map<String,Object> evidence() {
        Map<String,Object> out = new LinkedHashMap<String,Object>();
        out.put("schema", SCHEMA); out.put("kind", kind); out.put("package_name", packageName);
        out.put("owner_sha256", ownerSha256); out.put("contract_sha256", contractSha256);
        out.put("recognition", recognition); out.put("owner_start_utf16", 0);
        out.put("owner_end_utf16", immutableOwner.length()); out.put("owner_rewritten", false);
        out.put("source", "complete_immutable_owner_and_explicit_initial_package");
        out.put("tool_ceiling", Collections.unmodifiableList(new ArrayList<String>(toolCeiling)));
        if (FLIGHT_RESULTS.equals(kind)) {
            out.put("from_city", fromCity); out.put("to_city", toCity);
            out.put("departure_date", departureDate.toString()); out.put("trip_type", "one_way");
            out.put("adults", adults); out.put("children", children); out.put("infants", infants);
            out.put("date_start_utf16", dateStartUtf16); out.put("date_end_utf16", dateEndUtf16);
            out.put("from_start_utf16", fromStartUtf16); out.put("from_end_utf16", fromEndUtf16);
            out.put("to_start_utf16", toStartUtf16); out.put("to_end_utf16", toEndUtf16);
            out.put("airport_choice_inferred", false); out.put("year_explicit_in_owner", true);
        } else {
            out.put("product_model", productModel); out.put("model_start_utf16", modelStartUtf16);
            out.put("model_end_utf16", modelEndUtf16); out.put("variant_inferred", false);
            out.put("specifications_inferred", false); out.put("price_kind_inferred", false);
        }
        if(orderPreview!=null)out.put("order_preview",orderPreview.evidence());
        out.put("provider_support_claimed", false); out.put("installed_identity_verified", false);
        out.put("grants_tool_authority", false); out.put("query_executed", false);
        out.put("business_verified", false);
        return Collections.unmodifiableMap(out);
    }

    private String contractHash() {
        StringBuilder out = new StringBuilder();
        for (String value : new String[]{SCHEMA, kind, packageName, ownerSha256, recognition,
                fromCity, toCity, departureDate == null ? null : departureDate.toString(), productModel,
                Integer.toString(adults), Integer.toString(children), Integer.toString(infants),
                Integer.toString(dateStartUtf16), Integer.toString(dateEndUtf16),
                Integer.toString(fromStartUtf16), Integer.toString(fromEndUtf16),
                Integer.toString(toStartUtf16), Integer.toString(toEndUtf16),
                Integer.toString(modelStartUtf16), Integer.toString(modelEndUtf16)})
            field(out, value == null ? "" : value);
        if(orderPreview!=null){
            field(out,Integer.toString(orderPreview.quantity));field(out,orderPreview.capYuan);
            field(out,orderPreview.requestedVariant==null?"":orderPreview.requestedVariant);
            field(out,"stop_at_confirmation_without_submission_or_payment");
        }
        for (String tool : toolCeiling) field(out, tool);
        return hash(out.toString());
    }
    private static void field(StringBuilder out, String value) {
        out.append(value.getBytes(StandardCharsets.UTF_8).length).append(':').append(value).append('\n');
    }
    private static String packageForName(String name) {
        return "携程".equals(name) || "携程旅行".equals(name) ? CTRIP_PACKAGE
                : "南航".equals(name) || "中国南方航空".equals(name) ? CSAIR_PACKAGE : null;
    }
    private static boolean singleCity(String city) {
        return city != null && city.matches("[\\p{IsHan}]{2,12}") && !CITY_CONTROL.matcher(city).matches()
                && !city.contains("或") && !city.contains("与") && !city.contains("及")
                && city.indexOf('和') <= 0 && !city.contains("到") && !city.endsWith("的");
    }
    private static boolean valid(String owner) {
        if (owner == null || owner.isEmpty() || owner.getBytes(StandardCharsets.UTF_8).length > 1600
                || owner.contains("<|") || owner.contains("<__image__>")) return false;
        for (int i = 0; i < owner.length(); i++) {
            char c = owner.charAt(i);
            if (Character.isHighSurrogate(c)) {
                if (++i >= owner.length() || !Character.isLowSurrogate(owner.charAt(i))) return false;
            } else if (Character.isLowSurrogate(c) || Character.isISOControl(c)) return false;
        }
        return true;
    }
    private static String hash(String text) {
        try {
            byte[] bytes = MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
            char[] hex = "0123456789abcdef".toCharArray(); StringBuilder out = new StringBuilder(64);
            for (byte b : bytes) out.append(hex[(b >>> 4) & 15]).append(hex[b & 15]);
            return out.toString();
        } catch (NoSuchAlgorithmException impossible) { throw new IllegalStateException(impossible); }
    }
}
