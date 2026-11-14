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
    public static final String FLIGHT_RESULTS = "native_flight_results";
    public static final String CTRIP_PACKAGE = "ctrip.android.view";
    public static final String CSAIR_PACKAGE = "com.csair.mbp";
    public static final String XIAOMI_PACKAGE = "com.xiaomi.shop";
    public static final String PRODUCT_MODEL = "AX3000T";

    private static final Set<String> QUERY_TOOLS = Collections.unmodifiableSet(new TreeSet<String>(
            Arrays.asList("open", "click", "type", "submit", "scroll", "back", "wait", "done")));
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
    private static final Pattern PRODUCT = Pattern.compile(PREFIX
            + "(?:(?:在|用)小米商城(?:APP|App|app|应用)?(?:里|中|上)?)?"
            + "(?:查一下|查下|查询|查查|查看)(?:小米|Xiaomi)[ ]?(?:路由器[ ]?)?"
            + "(AX3000T)(?:的)?(?:售价|价格)[。？?]?", Pattern.CASE_INSENSITIVE);
    private static final Pattern PRODUCT_IN_APP = Pattern.compile(PREFIX
            + "(?:在|用)小米商城(?:APP|App|app|应用)?(?:里|中|上)?"
            + "(?:查一下|查下|查询|查查|查看)(?:路由器[ ]?)?"
            + "(AX3000T)(?:的)?(?:售价|价格)[。？?]?", Pattern.CASE_INSENSITIVE);
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
        kind = FLIGHT_RESULTS; packageName = selectedPackage; immutableOwner = owner; ownerSha256 = hash(owner);
        recognition = "complete_literal_native_single_adult_flight.v1"; toolCeiling = QUERY_TOOLS;
        departureDate = date; fromCity = match.group(5); toCity = match.group(6); productModel = null;
        adults = 1; children = 0; infants = 0;
        dateStartUtf16 = match.start(2); dateEndUtf16 = match.end(4) + suffix;
        fromStartUtf16 = match.start(5); fromEndUtf16 = match.end(5);
        toStartUtf16 = match.start(6); toEndUtf16 = match.end(6);
        modelStartUtf16 = modelEndUtf16 = -1;
        contractSha256 = contractHash();
    }

    private NativeAppGoal(String owner, String selectedPackage, Matcher match) {
        kind = PRODUCT_PRICE; packageName = selectedPackage; immutableOwner = owner; ownerSha256 = hash(owner);
        recognition = "complete_literal_native_ax3000t_price.v1"; toolCeiling = QUERY_TOOLS;
        departureDate = null; fromCity = toCity = null; productModel = PRODUCT_MODEL;
        adults = children = infants = -1;
        dateStartUtf16 = dateEndUtf16 = fromStartUtf16 = fromEndUtf16 = toStartUtf16 = toEndUtf16 = -1;
        modelStartUtf16 = match.start(1); modelEndUtf16 = match.end(1);
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
            Matcher match = FLIGHT_ZH.matcher(owner); int suffix = 1;
            if (!match.matches()) {
                match = FLIGHT_ISO.matcher(owner); suffix = 0;
                if (!match.matches()) return null;
            }
            String namedApp = match.group(1);
            if (namedApp != null && !explicitlySelectedPackage.equals(packageForName(namedApp))) return null;
            if (!singleCity(match.group(5)) || !singleCity(match.group(6))
                    || match.group(5).equals(match.group(6))) return null;
            try {
                LocalDate date = LocalDate.of(Integer.parseInt(match.group(2)),
                        Integer.parseInt(match.group(3)), Integer.parseInt(match.group(4)));
                if (date.getYear() < 1) return null;
                return new NativeAppGoal(owner, explicitlySelectedPackage, match, date, suffix);
            } catch (DateTimeException | NumberFormatException invalid) {
                return null;
            }
        }
        if (XIAOMI_PACKAGE.equals(explicitlySelectedPackage)) {
            Matcher match = PRODUCT.matcher(owner);
            if (!match.matches()) { match = PRODUCT_IN_APP.matcher(owner); if (!match.matches()) return null; }
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
