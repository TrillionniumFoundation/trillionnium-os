package org.trillionnium.hepta.local.web;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.DateTimeException;
import java.time.LocalDate;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Isolated candidate. A complete literal read-only flight goal, not tool authority.
 * The real phone TaskAuthorization must independently compile the identical OWNER.
 * This class neither opens a URL nor treats a query form as a flight result.
 */
public final class WebFlightGoal {
    public static final String SCHEMA = "hepta.web-flight-owner.csair.v1";
    public static final String NATURAL_SCHEMA = "hepta.web-flight-owner.csair.v2";
    public static final String NATURAL_RECOGNITION = "natural_explicit_date_single_adult_flight_query.v1";
    public static final String TAIL = "请核对实际出发日期、出发和到达机场、航班号、起降时间、公开显示的价格与币种，并注明价格包含或未注明的税费及条件。"
            + "只允许click、type、submit、scroll、back、wait、done。"
            + "输入和提交仅用于公开的城市、日期、人数及航班查询；不要登录、注册、同意授权、加购、预订、下单、支付或修改账号和权限。"
            + "遇到这些要求、访问阻断或资料不完整就停止并报告未完成。这是测试路线，不代表用户行程。";
    public static final String BACKGROUND_TAIL = TAIL.replace("只允许click、", "只允许open、click、");
    private static final Pattern OWNER = Pattern.compile(
            "网页查询测试：在南航官方网站查询([0-9]{4})年([0-9]{1,2})月([0-9]{1,2})日"
            + "([\\p{IsHan}]{2,12})到([\\p{IsHan}]{2,12})的单程航班，1名成人。" + Pattern.quote(TAIL));
    private static final Pattern BACKGROUND_OWNER = Pattern.compile(
            "网页查询测试：在南航官方网站查询([0-9]{4})年([0-9]{1,2})月([0-9]{1,2})日"
            + "([\\p{IsHan}]{2,12})到([\\p{IsHan}]{2,12})的单程航班，1名成人。" + Pattern.quote(BACKGROUND_TAIL));
    private static final String NATURAL_PREFIX = "(?:请)?(?:帮我)?(?:查一下|查询|查查)"
            + "(?:(?:南航|中国南方航空)(?:官网|官方网站)(?:上|的)?)?";
    private static final String NATURAL_ROUTE = "(?:从)?([\\p{IsHan}]{2,12}?)到([\\p{IsHan}]{2,12}?)"
            + "(?:的)?单程(?:机票|航班)[，,](?:1|一)(?:名|位)成人[。]?";
    private static final Pattern NATURAL_DATE = Pattern.compile(NATURAL_PREFIX
            + "([0-9]{4})年([0-9]{1,2})月([0-9]{1,2})日" + NATURAL_ROUTE);
    private static final Pattern NATURAL_ISO_DATE = Pattern.compile(NATURAL_PREFIX
            + "([0-9]{4})-([0-9]{2})-([0-9]{2})" + NATURAL_ROUTE);
    /** Recognition is not a grant; TaskAuthorization still compiles the original OWNER. */
    public final boolean naturalReadOnlyIntent;
    public final String contractSchema,recognition,providerSelection;
    /** Explicit OWNER token, not a grant and not proof that a background lease exists. */
    public final boolean ownerContainsOpen;
    public final String immutableOwner, ownerSha256, contractSha256, fromCity, toCity;
    public final LocalDate departureDate;
    public final int adults = 1, children = 0, infants = 0;
    public final int dateStartUtf16, dateEndUtf16, fromStartUtf16, fromEndUtf16, toStartUtf16, toEndUtf16;
    private WebFlightGoal(String owner, Matcher match, LocalDate date, boolean open) {
        this(owner,match,date,open,false,1);
    }
    private WebFlightGoal(String owner, Matcher match, LocalDate date, boolean open,boolean natural,int dateSuffix) {
        naturalReadOnlyIntent=natural;contractSchema=natural?NATURAL_SCHEMA:SCHEMA;
        recognition=natural?NATURAL_RECOGNITION:"literal_read_only_flight_test.v1";
        providerSelection=natural&&!owner.substring(0,match.start(1)).contains("南航")
                &&!owner.substring(0,match.start(1)).contains("中国南方航空")
                ?"compiled_official_csair_provider":"explicit_official_csair_owner";
        ownerContainsOpen = open;
        immutableOwner = owner;
        ownerSha256 = hash(owner);
        departureDate = date;
        fromCity = match.group(4); toCity = match.group(5);
        dateStartUtf16 = match.start(1); dateEndUtf16 = match.end(3) + dateSuffix;
        fromStartUtf16 = match.start(4); fromEndUtf16 = match.end(4);
        toStartUtf16 = match.start(5); toEndUtf16 = match.end(5);
        contractSha256 = hash(contractSchema + "\n" + ownerSha256 + "\n" + date.toString()
                + "\n" + fromCity + "\n" + toCity + "\n1\n0\n0\none_way");
    }
    /** Exact consumption only. Whitespace/suffixes, added goals or unknown syntax are unsupported. */
    public static WebFlightGoal parse(String owner) {
        if (owner == null || owner.getBytes(StandardCharsets.UTF_8).length > 1600) return null;
        Matcher match = OWNER.matcher(owner);
        boolean open = false;
        if (!match.matches()) {
            match = BACKGROUND_OWNER.matcher(owner);
            if (!match.matches()) return parseNatural(owner);
            open = true;
        }
        if (match.group(4).equals(match.group(5))) return null;
        try {
            LocalDate date = LocalDate.of(Integer.parseInt(match.group(1)),
                    Integer.parseInt(match.group(2)), Integer.parseInt(match.group(3)));
            return new WebFlightGoal(owner, match, date, open);
        } catch (DateTimeException | NumberFormatException invalid) {
            return null;
        }
    }
    private static WebFlightGoal parseNatural(String owner) {
        Matcher match=NATURAL_DATE.matcher(owner);int suffix=1;
        if(!match.matches()){match=NATURAL_ISO_DATE.matcher(owner);suffix=0;if(!match.matches())return null;}
        if(!singleCity(match.group(4))||!singleCity(match.group(5))||match.group(4).equals(match.group(5)))return null;
        try{
            LocalDate date=LocalDate.of(Integer.parseInt(match.group(1)),
                    Integer.parseInt(match.group(2)),Integer.parseInt(match.group(3)));
            return new WebFlightGoal(owner,match,date,false,true,suffix);
        }catch(DateTimeException|NumberFormatException invalid){return null;}
    }
    private static boolean singleCity(String city){
        return city.matches("[\\p{IsHan}]{2,12}")
                &&!city.matches(".*(?:或者|以及|然后|打开|查询|搜索|预订|下单|支付|删除|提醒|闹钟|成人|儿童|婴儿).*");
    }
    /** A recognized public-query purpose permits considering the compiled entry;
     * the real OWNER tool mask and selected background helper must also allow it.
     * No expanded or generated instruction is ever substituted for immutableOwner. */
    public boolean allowsInitialOfficialPage(){return ownerContainsOpen||naturalReadOnlyIntent;}
    /** Maximum purpose-compatible tools, never a grant. Intersect this with the
     * authorization compiled from the identical original OWNER and actual lease. */
    public Set<String> toolCeiling(){
        Set<String> ceiling=new TreeSet<String>(Arrays.asList("open","click","type","submit","scroll","back","wait","done"));
        if(!allowsInitialOfficialPage())ceiling.remove("open");
        return Collections.unmodifiableSet(ceiling);
    }
    /** Clock is supplied from the real task boundary, never inferred from page text. */
    public boolean departureNotBefore(LocalDate taskLocalDate) {
        return taskLocalDate != null && !departureDate.isBefore(taskLocalDate);
    }
    public Map<String,Object> evidence() {
        Map<String,Object> out = new LinkedHashMap<String,Object>();
        out.put("schema", contractSchema); out.put("owner_sha256", ownerSha256);
        out.put("contract_sha256", contractSha256); out.put("departure_date", departureDate.toString());
        out.put("from_city", fromCity); out.put("to_city", toCity); out.put("trip_type", "one_way");
        out.put("adults", adults); out.put("children", children); out.put("infants", infants);
        out.put("date_start_utf16", dateStartUtf16); out.put("date_end_utf16", dateEndUtf16);
        out.put("from_start_utf16", fromStartUtf16); out.put("from_end_utf16", fromEndUtf16);
        out.put("to_start_utf16", toStartUtf16); out.put("to_end_utf16", toEndUtf16);
        out.put("source", "complete_immutable_owner"); out.put("grants_tool_authority", false);
        out.put("airport_choice_inferred", false); out.put("query_executed", false);
        if(naturalReadOnlyIntent){
            out.put("recognition",recognition);out.put("provider_selection",providerSelection);
            out.put("owner_rewritten",false);out.put("year_explicit_in_owner",true);
            out.put("owner_contains_literal_open",ownerContainsOpen);out.put("initial_official_page_required",true);
        }
        return Collections.unmodifiableMap(out);
    }
    static String hash(String value) {
        try {
            byte[] bytes = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            char[] hex = "0123456789abcdef".toCharArray(); StringBuilder out = new StringBuilder(64);
            for (byte b : bytes) out.append(hex[(b >>> 4) & 15]).append(hex[b & 15]);
            return out.toString();
        } catch (Exception impossible) { throw new IllegalStateException(impossible); }
    }
}
