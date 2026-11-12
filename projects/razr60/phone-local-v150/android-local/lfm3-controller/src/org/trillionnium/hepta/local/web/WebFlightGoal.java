package org.trillionnium.hepta.local.web;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.DateTimeException;
import java.time.LocalDate;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Isolated candidate. A complete literal read-only flight goal, not tool authority.
 * The real phone TaskAuthorization must independently compile the identical OWNER.
 * This class neither opens a URL nor treats a query form as a flight result.
 */
public final class WebFlightGoal {
    public static final String SCHEMA = "hepta.web-flight-owner.csair.v1";
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
    /** Explicit OWNER token, not a grant and not proof that a background lease exists. */
    public final boolean ownerContainsOpen;
    public final String immutableOwner, ownerSha256, contractSha256, fromCity, toCity;
    public final LocalDate departureDate;
    public final int adults = 1, children = 0, infants = 0;
    public final int dateStartUtf16, dateEndUtf16, fromStartUtf16, fromEndUtf16, toStartUtf16, toEndUtf16;
    private WebFlightGoal(String owner, Matcher match, LocalDate date, boolean open) {
        ownerContainsOpen = open;
        immutableOwner = owner;
        ownerSha256 = hash(owner);
        departureDate = date;
        fromCity = match.group(4); toCity = match.group(5);
        dateStartUtf16 = match.start(1); dateEndUtf16 = match.end(3) + 1;
        fromStartUtf16 = match.start(4); fromEndUtf16 = match.end(4);
        toStartUtf16 = match.start(5); toEndUtf16 = match.end(5);
        contractSha256 = hash(SCHEMA + "\n" + ownerSha256 + "\n" + date.toString()
                + "\n" + fromCity + "\n" + toCity + "\n1\n0\n0\none_way");
    }
    /** Exact consumption only. Whitespace/suffixes, added goals or unknown syntax are unsupported. */
    public static WebFlightGoal parse(String owner) {
        if (owner == null || owner.getBytes(StandardCharsets.UTF_8).length > 1600) return null;
        Matcher match = OWNER.matcher(owner);
        boolean open = false;
        if (!match.matches()) {
            match = BACKGROUND_OWNER.matcher(owner);
            if (!match.matches()) return null;
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
    /** Clock is supplied from the real task boundary, never inferred from page text. */
    public boolean departureNotBefore(LocalDate taskLocalDate) {
        return taskLocalDate != null && !departureDate.isBefore(taskLocalDate);
    }
    public Map<String,Object> evidence() {
        Map<String,Object> out = new LinkedHashMap<String,Object>();
        out.put("schema", SCHEMA); out.put("owner_sha256", ownerSha256);
        out.put("contract_sha256", contractSha256); out.put("departure_date", departureDate.toString());
        out.put("from_city", fromCity); out.put("to_city", toCity); out.put("trip_type", "one_way");
        out.put("adults", adults); out.put("children", children); out.put("infants", infants);
        out.put("date_start_utf16", dateStartUtf16); out.put("date_end_utf16", dateEndUtf16);
        out.put("from_start_utf16", fromStartUtf16); out.put("from_end_utf16", fromEndUtf16);
        out.put("to_start_utf16", toStartUtf16); out.put("to_end_utf16", toEndUtf16);
        out.put("source", "complete_immutable_owner"); out.put("grants_tool_authority", false);
        out.put("airport_choice_inferred", false); out.put("query_executed", false);
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
