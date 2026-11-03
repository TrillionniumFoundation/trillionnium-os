package org.trillionnium.owneropen;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;

/**
 * Presentation-only projection of the existing owner-open wire.
 *
 * The caller passes the very same turn evidence it has already correlated in
 * onFrame. Nothing in this class connects, dispatches, releases a hold, changes
 * a turn identity, or creates completion authority. Unknown records remain in
 * the caller's original transcript. Entries with the same key replace a view.
 */
public final class OwnerOpenUiEventFormatter {
    public enum Role { USER, ASSISTANT, TOOL, STATUS, ERROR }

    public static final class Entry {
        public final String key;
        public final Role role;
        public final String text;
        public final boolean replace;
        public final boolean historical;

        public Entry(String key, Role role, String text, boolean replace, boolean historical) {
            this.key = key;
            this.role = role;
            this.text = text;
            this.replace = replace;
            this.historical = historical;
        }
    }

    private static final String USER_JSON = "ui.user.json:";
    private static final String USER_LEGACY = "ui.user:";
    private static final int MAX_TEXT_CHARS = 65_536;
    private static final int MAX_REMEMBERED_ENTRIES = 96;
    private static final int MAX_CONTENT_BLOCKS = 64;
    private static final int MAX_REMEMBERED_EVENTS = 512;
    private final LinkedHashMap<String, Entry> rendered = new LinkedHashMap<>();
    private final LinkedHashSet<String> finishedTurns = new LinkedHashSet<>();
    // Only the selected turn needs an incremental body. Earlier turns already
    // have their bounded display entries in the Activity's timeline cache.
    private TurnProjection live;
    private long nextLegacyUser;
    private String currentTurnKey = "turn:pending";

    /** One local display record, with line breaks/quotes preserved in JSONL. */
    public static String userRecord(String turnId, String text) {
        if (turnId == null || turnId.isEmpty() || text == null)
            throw new IllegalArgumentException("a local user record needs its turn and text");
        return USER_JSON + "{\"turn_id\":" + OwnerOpenFrame.quote(turnId)
                + ",\"text\":" + OwnerOpenFrame.quote(text) + "}";
    }

    /**
     * Formats a current record. verifiedEvidence must be null for a turn frame
     * that the Activity rejected, including stale or unsolicited readbacks.
     */
    public List<Entry> accept(String raw, boolean chinese,
            OwnerOpenTurnEvidence verifiedEvidence) {
        if (verifiedEvidence != null) return acceptWire(raw, chinese, verifiedEvidence);
        return acceptInternal(raw, chinese, verifiedEvidence, false);
    }

    /**
     * The onFrame path must use this entry point, even for a rejected frame.
     * Wire bytes can never acquire the provenance of a local ui.user record or
     * local request log merely by beginning with the same characters.
     */
    public List<Entry> acceptWire(String raw, boolean chinese,
            OwnerOpenTurnEvidence verifiedEvidence) {
        return acceptWire(raw, chinese, verifiedEvidence, null);
    }

    /**
     * The selected state is the Activity's existing immutable identity snapshot.
     * It scopes live observations for display only. This overload does not parse
     * a completion proof, persist a cursor or change the selected execution state.
     */
    public List<Entry> acceptWire(String raw, boolean chinese,
            OwnerOpenTurnEvidence verifiedEvidence, OwnerOpenClientState selected) {
        if (raw == null) return Collections.emptyList();
        String json = raw.stripLeading();
        if (!json.startsWith("{")) return Collections.emptyList();
        if (verifiedEvidence == null && selected != null) {
            try {
                Map<String, Object> envelope = OwnerOpenTurnEvidence.decodeForDisplay(json);
                if ("observation".equals(envelope.get("kind")))
                    return acceptObservation(envelope, selected, chinese);
            } catch (RuntimeException malformedDisplayRecord) {
                return Collections.emptyList();
            }
        }
        return acceptInternal(json, chinese, verifiedEvidence, false);
    }

    /**
     * Recovery is limited to records whose local display provenance is known.
     * A raw transcript also contains rejected wire frames; those must NEVER be
     * promoted to a saved answer by parsing them again. The Activity can restore
     * previously displayed entries from its separate STATE_UI_TIMELINE cache,
     * marking them historical without touching any execution state.
     * Do not call this on the mixed legacy raw transcript: a rejected wire line
     * there may impersonate even a ui.user prefix.
     */
    public List<Entry> acceptHistory(String raw, boolean chinese) {
        if (raw == null || (!raw.startsWith(USER_JSON) && !raw.startsWith(USER_LEGACY)))
            return Collections.emptyList();
        return acceptInternal(raw, chinese, null, true);
    }

    public void clear() {
        rendered.clear();
        finishedTurns.clear();
        live = null;
        nextLegacyUser = 0;
        currentTurnKey = "turn:pending";
    }

    private List<Entry> acceptInternal(String raw, boolean chinese,
            OwnerOpenTurnEvidence verifiedEvidence, boolean historical) {
        if (raw == null || raw.isEmpty()) return Collections.emptyList();
        LinkedHashMap<String, Entry> changes = new LinkedHashMap<>();
        try {
            if (raw.startsWith(USER_JSON)) {
                Map<String, Object> value = OwnerOpenTurnEvidence.decodeForDisplay(
                        raw.substring(USER_JSON.length()));
                String turnId = string(value.get("turn_id"));
                String text = string(value.get("text"));
                if (turnId.isEmpty() || turnId.length() > 256 || text.isBlank())
                    return Collections.emptyList();
                currentTurnKey = "turn:" + turnId;
                put(changes, currentTurnKey + ":user", Role.USER, text, chinese, historical);
            } else if (raw.startsWith(USER_LEGACY)) {
                put(changes, "legacy-user:" + (++nextLegacyUser), Role.USER,
                        raw.substring(USER_LEGACY.length()), chinese, historical);
            } else if (raw.startsWith("local request_id=")) {
                // The reader can deliver acceptance before startTurn returns.
                // A later local log line must not roll that receipt backwards.
                if (!rendered.containsKey(currentTurnKey + ":status"))
                    status(changes, currentTurnKey,
                            choose(chinese, "正在等待响应", "Waiting for a response"),
                            false, chinese, historical);
            } else if (raw.equals("local: reconnected")) {
                put(changes, "connection", Role.STATUS,
                        choose(chinese, "已连接", "Connected"), chinese, historical);
            } else if (raw.startsWith("local disconnected:")) {
                put(changes, "connection", Role.ERROR,
                        choose(chinese, "连接已断开", "Disconnected"), chinese, historical);
            } else if (raw.startsWith("local turn.start failed:")
                    || raw.startsWith("local turn.inspect failed:")
                    || raw.startsWith("local turn.cancel failed:")) {
                // A newly selected turn can fail before its userRecord is
                // emitted. This transport log has no explicit turn identity;
                // never attach it to whichever turn was displayed previously.
                String text = raw.startsWith("local turn.start failed:")
                        ? choose(chinese, "发送结果待确认，可查看详情", "Send outcome unconfirmed · see details")
                        : raw.startsWith("local turn.inspect failed:")
                        ? choose(chinese, "暂未读到记录，可查看详情", "Readback unavailable · see details")
                        : choose(chinese, "取消结果待确认，可查看详情", "Cancellation unconfirmed · see details");
                put(changes, "operation:status", Role.ERROR, text, chinese, historical);
            } else if (raw.startsWith("{")) {
                Map<String, Object> envelope = OwnerOpenTurnEvidence.decodeForDisplay(raw);
                String kind = string(envelope.get("kind"));
                if ("result".equals(kind) && verifiedEvidence != null) {
                    formatVerifiedResult(changes, envelope, verifiedEvidence, chinese, historical);
                } else if ("broker.hello.ack".equals(kind)) {
                    put(changes, "connection", Role.STATUS,
                            choose(chinese, "已连接", "Connected"), chinese, historical);
                } else if ("emergency.result".equals(kind)) {
                    // These are observations from the existing control reply,
                    // not a claim that earlier work was undone or quiescent.
                    if (Boolean.TRUE.equals(envelope.get("dispatch_inhibited"))) {
                        put(changes, "control", Role.STATUS,
                                choose(chinese, "后续任务已暂停", "Further dispatch is paused"),
                                chinese, historical);
                    } else if (Boolean.TRUE.equals(envelope.get("stop_requested"))) {
                        put(changes, "control", Role.STATUS,
                                choose(chinese, "已收到停止请求", "Stop request received"),
                                chinese, historical);
                    } else {
                        put(changes, "control", Role.STATUS,
                                choose(chinese, "设备状态已读取", "Device status received"),
                                chinese, historical);
                    }
                }
            } else if (raw.startsWith("local")) {
                LocalNotice notice = localNotice(raw, chinese);
                if (notice != null)
                    put(changes, "operation:status", notice.role, notice.text, chinese, historical);
            }
        } catch (RuntimeException malformedDisplayRecord) {
            // The caller keeps the original bytes in its details transcript.
            // Malformed/oversized/unrecognized data never becomes an answer.
            return Collections.emptyList();
        }
        return publish(changes);
    }

    private void formatVerifiedResult(Map<String, Entry> changes, Map<String, Object> envelope,
            OwnerOpenTurnEvidence evidence, boolean chinese, boolean historical) {
        Map<String, Object> frame = object(envelope.get("frame"));
        // Mechanical pairing with the supplied proof; this does not replace the
        // Activity's existing selected-identity and pending-inspection checks.
        if (!evidence.kind.equals(frame.get("kind"))
                || !evidence.brokerRequestId.equals(envelope.get("request_id"))
                || !evidence.sessionId.equals(frame.get("session_id"))
                || !evidence.taskId.equals(frame.get("task_id"))
                || !evidence.turnId.equals(frame.get("turn_id"))) return;
        currentTurnKey = "turn:" + evidence.turnId;
        Map<String, Object> payload = object(frame.get("payload"));
        if ("turn.accepted".equals(evidence.kind)) {
            if (!finishedTurns.contains(currentTurnKey))
                status(changes, currentTurnKey,
                        choose(chinese, "已受理，等待结果", "Accepted · waiting for a result"),
                        false, chinese, historical);
            return;
        }
        if (!"turn.inspect.result".equals(evidence.kind)) return;

        List<?> frames = list(payload.get("frames"));
        TurnProjection readback = new TurnProjection(currentTurnKey, evidence.requestSha256);
        for (Object value : frames) readback.observe(object(value));

        // A zero-cursor readback can arrive while the live stream has advanced.
        // Its older prefix must not erase text already displayed from that same
        // stream. A complete readback always supplies the canonical projection.
        TurnProjection body = readback;
        if (!evidence.completeReadback && live != null
                && live.sameScope(currentTurnKey, evidence.requestSha256)
                && live.lastSequence > readback.lastSequence) {
            body = live;
        } else {
            live = readback;
        }
        body.render(changes, chinese, historical);
        if (evidence.completeReadback && !readback.terminalStatus.isEmpty()) {
            terminal(changes, currentTurnKey, readback.terminalStatus, chinese, historical);
            rememberFinished(currentTurnKey);
        } else if (finishedTurns.contains(currentTurnKey)) {
            // A late partial readback is still useful in details, but cannot
            // regress the UI's already observed terminal status.
        } else if (Boolean.TRUE.equals(payload.get("has_more"))) {
            status(changes, currentTurnKey,
                    choose(chinese, "已读取部分记录", "Partial records received"),
                    false, chinese, historical);
        } else if ("found".equals(payload.get("status"))) {
            status(changes, currentTurnKey,
                    body.providerStatus.isBlank()
                            ? choose(chinese, "已读取最新记录", "Latest records received")
                            : choose(chinese, "进度：", "Progress: ") + body.providerStatus,
                    false, chinese, historical);
        } else {
            status(changes, currentTurnKey,
                    choose(chinese, "暂未取得本轮结果", "No turn result available yet"),
                    false, chinese, historical);
        }
    }

    private List<Entry> acceptObservation(Map<String, Object> envelope,
            OwnerOpenClientState selected, boolean chinese) {
        if (!"org.trillionnium.owner-open.connection-broker-wire.v1".equals(envelope.get("schema"))
                || !Boolean.FALSE.equals(envelope.get("automatic_redispatch"))
                || selected.turnId == null || selected.turnRequestSha256 == null)
            return Collections.emptyList();
        Map<String, Object> frame = object(envelope.get("frame"));
        String kind = string(frame.get("kind"));
        // The broker also broadcasts turn.inspect.result as an observation.
        // Such a broadcast has no pending-inspect request association. Only the
        // existing Activity-verified result path may project its nested frames.
        if (!isLiveKind(kind)) return Collections.emptyList();
        Map<String, Object> payload = object(frame.get("payload"));
        String stream = OwnerOpenFrame.turnStreamId(
                selected.sessionId, selected.taskId, selected.turnId);
        String eventId = string(frame.get("event_id"));
        if (!selected.sessionId.equals(frame.get("session_id"))
                || !selected.taskId.equals(frame.get("task_id"))
                || !selected.turnId.equals(frame.get("turn_id"))
                || !selected.turnRequestSha256.equals(payload.get("turn_request_sha256"))
                || !stream.equals(frame.get("stream_id"))
                || !stream.equals(frame.get("turn_stream_id"))
                || !"owner-open".equals(frame.get("profile_id"))
                || !"host_to_client".equals(frame.get("direction"))
                || eventId.isEmpty() || eventId.length() > 256
                || !nonnegative(frame.get("host_seq")) || !nonnegative(frame.get("seq"))
                || (frame.containsKey("core_host_seq") && !nonnegative(frame.get("core_host_seq"))))
            return Collections.emptyList();
        if ("turn.accepted".equals(kind) && !"accepted".equals(payload.get("status")))
            return Collections.emptyList();
        if (kind.startsWith("tool.") && (string(frame.get("call_id")).isEmpty()
                || string(frame.get("call_id")).length() > 256))
            return Collections.emptyList();

        currentTurnKey = "turn:" + selected.turnId;
        if (live == null || !live.sameScope(currentTurnKey, selected.turnRequestSha256))
            live = new TurnProjection(currentTurnKey, selected.turnRequestSha256);
        if (!live.observe(frame)) return Collections.emptyList();
        LinkedHashMap<String, Entry> changes = new LinkedHashMap<>();
        live.render(changes, chinese, false);
        if ("turn.end".equals(kind)) {
            terminal(changes, currentTurnKey, live.terminalStatus, chinese, false);
            // This set only avoids regressing text. It is not readback evidence
            // and is never exposed as authority to enable Send or clear Stop.
            rememberFinished(currentTurnKey);
        } else if (!finishedTurns.contains(currentTurnKey)) {
            if ("turn.accepted".equals(kind)) {
                status(changes, currentTurnKey,
                        choose(chinese, "已受理，等待结果", "Accepted · waiting for a result"),
                        false, chinese, false);
            } else if ("provider.status".equals(kind) && !live.providerStatus.isBlank()) {
                status(changes, currentTurnKey,
                        choose(chinese, "进度：", "Progress: ") + live.providerStatus,
                        false, chinese, false);
            } else if ("tool.accepted".equals(kind) || "tool.started".equals(kind)) {
                String tool = string(frame.get("tool"));
                String text = "tool.started".equals(kind)
                        ? choose(chinese, "正在执行", "Running")
                        : choose(chinese, "执行请求已受理", "Tool request accepted");
                status(changes, currentTurnKey, text + (tool.isBlank() ? "" : " · " + tool),
                        false, chinese, false);
            }
        }
        return publish(changes);
    }

    private static boolean isLiveKind(String kind) {
        return "turn.accepted".equals(kind) || "turn.end".equals(kind)
                || "model.delta".equals(kind) || "model.message".equals(kind)
                || "provider.status".equals(kind) || "tool.accepted".equals(kind)
                || "tool.started".equals(kind) || "tool.stdout".equals(kind)
                || "tool.stderr".equals(kind) || "tool.result".equals(kind);
    }

    private static boolean nonnegative(Object value) {
        return value instanceof Long && (Long) value >= 0;
    }

    private void rememberFinished(String turnKey) {
        finishedTurns.add(turnKey);
        while (finishedTurns.size() > MAX_REMEMBERED_ENTRIES)
            finishedTurns.remove(finishedTurns.iterator().next());
    }

    private void terminal(Map<String, Entry> changes, String turnKey, String state,
            boolean chinese, boolean historical) {
        String text;
        boolean failed = false;
        switch (state) {
            case "completed":
                text = choose(chinese, "本轮已结束", "Turn finished");
                break;
            case "cancelled":
                text = choose(chinese, "本轮已取消", "Turn cancelled");
                break;
            case "provider_failed":
                text = choose(chinese, "生成服务未完成本轮请求", "The provider could not finish this turn");
                failed = true;
                break;
            case "provider_panicked":
                text = choose(chinese, "生成服务出现异常", "The provider encountered an error");
                failed = true;
                break;
            case "host_failed":
                text = choose(chinese, "服务处理本轮请求时出错", "The host could not finish this turn");
                failed = true;
                break;
            default:
                text = choose(chinese, "本轮结果待确认", "Turn outcome remains unconfirmed");
        }
        status(changes, turnKey, text, failed, chinese, historical);
    }

    private void status(Map<String, Entry> changes, String turnKey, String text,
            boolean error, boolean chinese, boolean historical) {
        put(changes, turnKey + ":status", error ? Role.ERROR : Role.STATUS,
                text, chinese, historical);
    }

    private void put(Map<String, Entry> changes, String key, Role role, String text,
            boolean chinese, boolean historical) {
        if (text == null || text.isBlank()) return;
        if (text.length() > MAX_TEXT_CHARS) {
            int end = MAX_TEXT_CHARS;
            if (Character.isHighSurrogate(text.charAt(end - 1))) end--;
            text = text.substring(0, end) + shortened(chinese);
        }
        changes.put(key, new Entry(key, role, text, true, historical));
    }

    private List<Entry> publish(Map<String, Entry> changes) {
        ArrayList<Entry> result = new ArrayList<>();
        for (Entry next : changes.values()) {
            Entry prior = rendered.get(next.key);
            if (prior != null && prior.role == next.role && prior.text.equals(next.text)
                    && prior.historical == next.historical) continue;
            Entry update = new Entry(next.key, next.role, next.text, prior != null, next.historical);
            rendered.put(next.key, update);
            result.add(update);
        }
        while (rendered.size() > MAX_REMEMBERED_ENTRIES)
            rendered.remove(rendered.keySet().iterator().next());
        return Collections.unmodifiableList(result);
    }

    private static String string(Object value) {
        return value instanceof String ? (String) value : "";
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object value) {
        if (!(value instanceof Map<?, ?>)) throw new IllegalArgumentException("object required");
        return (Map<String, Object>) value;
    }

    private static List<?> list(Object value) {
        if (!(value instanceof List<?>)) throw new IllegalArgumentException("array required");
        return (List<?>) value;
    }

    private static String choose(boolean chinese, String zh, String en) {
        return chinese ? zh : en;
    }

    private static String shortened(boolean chinese) {
        return choose(chinese, "\n…（界面仅显示部分内容）", "\n… (only part of the content is shown)");
    }

    /** Bounded body shared by live observations and already verified readback. */
    private final class TurnProjection {
        final String turnKey;
        final String requestDigest;
        final LinkedHashMap<String, Object> content = new LinkedHashMap<>();
        final LinkedHashSet<String> eventIds = new LinkedHashSet<>();
        final DisplayBudget budget = new DisplayBudget();
        ModelText deltas;
        ModelText lastMessage;
        long lastSequence = -1;
        String terminalStatus = "";
        String terminalSummary = "";
        String providerStatus = "";
        boolean terminalSeen;

        TurnProjection(String turnKey, String requestDigest) {
            this.turnKey = turnKey;
            this.requestDigest = requestDigest;
        }

        boolean sameScope(String key, String digest) {
            return turnKey.equals(key) && requestDigest.equals(digest);
        }

        boolean observe(Map<String, Object> event) {
            String eventId = string(event.get("event_id"));
            // The transport retains core_host_seq when rewriting its own Host
            // counter. Stored inspect frames contain the original host_seq.
            Object sequence = event.containsKey("core_host_seq")
                    ? event.get("core_host_seq") : event.get("host_seq");
            if (!nonnegative(sequence) || terminalSeen || eventIds.contains(eventId)
                    || (Long) sequence <= lastSequence) return false;
            Map<String, Object> payload = object(event.get("payload"));
            String kind = string(event.get("kind"));
            eventIds.add(eventId);
            while (eventIds.size() > MAX_REMEMBERED_EVENTS)
                eventIds.remove(eventIds.iterator().next());
            lastSequence = (Long) sequence;
            if ("turn.end".equals(kind)) {
                terminalSeen = true;
                terminalStatus = limitedString(payload.get("status"));
                terminalSummary = limitedString(payload.get("summary"));
            } else if ("model.delta".equals(kind)) {
                String text = string(payload.get("text"));
                if (text.isEmpty()) return true;
                if (deltas == null) {
                    if (content.size() >= MAX_CONTENT_BLOCKS) return true;
                    deltas = new ModelText(budget);
                    content.put(turnKey + ":answer:" + eventId, deltas);
                }
                deltas.append(text);
                lastMessage = deltas;
            } else if ("model.message".equals(kind)) {
                String text = string(payload.get("text"));
                if (text.isBlank()) return true;
                if (deltas != null && text.startsWith(deltas.text.toString())) {
                    deltas.replace(text);
                    lastMessage = deltas;
                } else if (content.size() < MAX_CONTENT_BLOCKS) {
                    lastMessage = new ModelText(budget);
                    lastMessage.append(text);
                    content.put(turnKey + ":answer:" + eventId, lastMessage);
                }
                deltas = null;
            } else if ("provider.status".equals(kind)) {
                providerStatus = limitedString(payload.get("detail"));
                if (providerStatus.isBlank()) providerStatus = limitedString(payload.get("status"));
            } else if ("tool.accepted".equals(kind) || "tool.started".equals(kind)
                    || "tool.stdout".equals(kind) || "tool.stderr".equals(kind)
                    || "tool.result".equals(kind)) {
                String callId = string(event.get("call_id"));
                if (callId.isEmpty() || callId.length() > 256) return true;
                deltas = null;
                String key = turnKey + ":tool:" + callId;
                ToolOutput tool = (ToolOutput) content.get(key);
                if (tool == null) {
                    if (content.size() >= MAX_CONTENT_BLOCKS) return true;
                    tool = new ToolOutput(limitedString(event.get("tool")), budget);
                    content.put(key, tool);
                }
                tool.observe(kind, payload);
            }
            return true;
        }

        void render(Map<String, Entry> changes, boolean chinese, boolean historical) {
            for (Map.Entry<String, Object> item : content.entrySet()) {
                if (item.getValue() instanceof ModelText) {
                    ModelText model = (ModelText) item.getValue();
                    if (model.text.length() > 0)
                        put(changes, item.getKey(), Role.ASSISTANT,
                                model.text.toString() + (model.truncated ? shortened(chinese) : ""),
                                chinese, historical);
                } else {
                    String text = ((ToolOutput) item.getValue()).display(chinese);
                    if (!text.isEmpty()) put(changes, item.getKey(), Role.TOOL, text, chinese, historical);
                }
            }
            if (!terminalSummary.isBlank()
                    && (lastMessage == null || !terminalSummary.equals(lastMessage.text.toString())))
                put(changes, turnKey + ":summary", Role.ASSISTANT,
                        terminalSummary, chinese, historical);
        }
    }

    private static String limitedString(Object value) {
        String text = string(value);
        if (text.length() <= MAX_TEXT_CHARS) return text;
        int end = MAX_TEXT_CHARS;
        if (Character.isHighSurrogate(text.charAt(end - 1))) end--;
        // Keep one extra character so put() can add its localized truncation
        // marker, without retaining an arbitrarily large provider field.
        return text.substring(0, end) + "…";
    }

    private static final class DisplayBudget {
        int remaining = 262_144;
        int take(int requested) {
            int used = Math.min(remaining, requested);
            remaining -= used;
            return used;
        }
    }

    private static final class ModelText {
        final StringBuilder text = new StringBuilder();
        final DisplayBudget budget;
        boolean truncated;

        ModelText(DisplayBudget budget) { this.budget = budget; }

        void append(String next) {
            if (truncated) return;
            int count = Math.min(next.length(), Math.min(MAX_TEXT_CHARS - text.length(), budget.remaining));
            if (count > 0 && count < next.length() && Character.isHighSurrogate(next.charAt(count - 1)))
                count--;
            text.append(next, 0, count);
            budget.take(count);
            truncated = count < next.length();
        }

        void replace(String next) {
            budget.remaining += text.length();
            text.setLength(0);
            truncated = false;
            append(next);
        }
    }

    private static final class LocalNotice {
        final Role role;
        final String text;
        LocalNotice(boolean error, String text) {
            this.role = error ? Role.ERROR : Role.STATUS;
            this.text = text;
        }
    }

    private static LocalNotice localNotice(String raw, boolean chinese) {
        String zh;
        String en;
        boolean error = false;
        if (raw.equals("local: prompt is empty")) {
            zh = "请先输入问题或任务"; en = "Enter a question or task first";
        } else if (raw.equals("local: no turn has been started")) {
            zh = "还没有可查看的任务"; en = "There is no task to inspect yet";
        } else if (raw.startsWith("local: selected turn is already terminal")) {
            zh = "本轮已经结束，无需再次取消"; en = "This turn has already finished";
        } else if (raw.startsWith("local: Cancel held until durable identity is ready")
                || raw.startsWith("local: Inspect held until durable identity is ready")
                || raw.startsWith("local: durable identity is loading")) {
            zh = "会话正在准备，请稍候"; en = "Preparing the session";
        } else if (raw.startsWith("local: durable identity unavailable")) {
            zh = "无法读取会话状态，可查看详情"; en = "Session state is unavailable · see details";
            error = true;
        } else if (raw.startsWith("local: identity/control state is loading, inhibited or unavailable")) {
            zh = "请在操作中查看连接与控制状态"; en = "Check connection and control status in Actions";
        } else if (raw.startsWith("local: Send blocked by unavailable identity or unknown receipt")) {
            zh = "上一轮结果待确认，可在操作中查看记录"; en = "Check the previous turn's result in Actions";
        } else if (raw.startsWith("local: original request digest missing")) {
            zh = "当前任务记录不完整，可查看详情"; en = "The saved task record is incomplete · see details";
            error = true;
        } else if (raw.startsWith("local: explicit initialization recorded")) {
            zh = "已启用新任务"; en = "New turns enabled";
        } else if (raw.startsWith("local: new turns already allowed")) {
            zh = "新任务已处于启用状态"; en = "New turns are already enabled";
        } else if (raw.startsWith("local: explicitly refreshed committed initialization")) {
            zh = "已更新启用状态"; en = "Enabled state refreshed";
        } else if (raw.startsWith("local: initialization cannot clear an emergency intent")
                || raw.startsWith("local: emergency or unavailable local control state retained")) {
            zh = "当前处于暂停状态，请先查看停止状态"; en = "Dispatch is paused · check Stop status";
        } else if (raw.startsWith("local: initialization refused")) {
            zh = "设备暂停状态尚未解除或确认"; en = "The device pause state remains set or unconfirmed";
        } else if (raw.startsWith("local: initialization persistence failed")
                || raw.startsWith("local initialization persistence failed")) {
            zh = "控制状态未能保存，可查看详情"; en = "Control state could not be saved · see details";
            error = true;
        } else if (raw.startsWith("local initialization unknown")) {
            zh = "控制状态暂未确认，可查看详情"; en = "Control state is unconfirmed · see details";
            error = true;
        } else if (raw.startsWith("local: explicit emergency intent latched")) {
            zh = "本地发送已暂停，正在请求停止"; en = "Local sending is paused · requesting Stop";
        } else if (raw.startsWith("local emergency delivery unknown")
                || raw.startsWith("local emergency status unknown")
                || raw.startsWith("local stop queue unavailable")
                || raw.startsWith("local control queue unavailable")) {
            zh = "停止请求状态待确认，可查看详情"; en = "Stop request status is unconfirmed · see details";
            error = true;
        } else if (raw.equals("local: durable local emergency intent=true")
                || raw.startsWith("local: durable local emergency intent=true;")) {
            zh = "已保存停止设置"; en = "Stop settings saved";
        } else if (raw.startsWith("local emergency persistence failed")
                || raw.startsWith("local emergency persistence unavailable")
                || raw.startsWith("local: durable local emergency intent=")) {
            zh = "停止记录需要确认，可查看详情"; en = "The saved Stop record needs checking · see details";
            error = true;
        } else if (raw.equals("local: no local emergency intent")) {
            zh = "本地没有停止请求"; en = "There is no local Stop request";
        } else if (raw.startsWith("local: stale or unrequested inspection")
                || raw.startsWith("local: invalid or conflicting readback")) {
            zh = "这份记录尚未确认，可查看详情"; en = "This readback is unconfirmed · see details";
            error = true;
        } else if (raw.startsWith("local reconnect failed:")) {
            zh = "连接未成功，可重试"; en = "Connection failed · try reconnecting";
            error = true;
        } else {
            return null;
        }
        return new LocalNotice(error, choose(chinese, zh, en));
    }

    /** Fields verified against the retained real Host inspect envelope. */
    private static final class ToolOutput {
        final String tool;
        final OutputStreamText stdout;
        final OutputStreamText stderr;
        String terminalKind = "";
        Long exitCode;
        boolean ended;
        boolean outputTruncated;

        ToolOutput(String tool, DisplayBudget budget) {
            this.tool = tool;
            this.stdout = new OutputStreamText(budget);
            this.stderr = new OutputStreamText(budget);
        }

        void observe(String kind, Map<String, Object> payload) {
            if ("tool.stdout".equals(kind)) stdout.append(payload);
            else if ("tool.stderr".equals(kind)) stderr.append(payload);
            else if ("tool.result".equals(kind)) {
                ended = "terminal".equals(payload.get("status"));
                terminalKind = string(payload.get("terminal_kind"));
                Object code = payload.get("exit_code");
                exitCode = code instanceof Long ? (Long) code : null;
                outputTruncated = Boolean.TRUE.equals(payload.get("output_truncated"));
            }
        }

        String display(boolean chinese) {
            String out = stdout.text(ended);
            String err = stderr.text(ended);
            if (out.isEmpty() && err.isEmpty() && !ended) return "";
            StringBuilder text = new StringBuilder(choose(chinese, "执行输出", "Tool output"));
            if (!tool.isBlank()) text.append(" · ").append(tool);
            if (!out.isEmpty()) text.append('\n').append(out);
            if (!err.isEmpty()) text.append('\n').append(
                    choose(chinese, "诊断输出：\n", "Standard error:\n")).append(err);
            if (stdout.binary || stderr.binary)
                text.append('\n').append(choose(chinese,
                        "二进制输出见详情", "Binary output is available in details"));
            if (ended && "exited".equals(terminalKind) && exitCode != null)
                text.append('\n').append(choose(chinese, "进程退出 · 退出码 ", "Process exited · code "))
                        .append(exitCode);
            else if (ended)
                text.append('\n').append(choose(chinese, "进程记录已返回", "Process observation received"));
            if (outputTruncated)
                text.append('\n').append(choose(chinese, "输出有截断", "Output was truncated"));
            if (stdout.truncated || stderr.truncated) text.append(shortened(chinese));
            return text.toString();
        }
    }

    private static final class OutputStreamText {
        final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        final DisplayBudget budget;
        boolean malformed;
        boolean binary;
        boolean truncated;

        OutputStreamText(DisplayBudget budget) { this.budget = budget; }

        void append(Map<String, Object> payload) {
            if (malformed || truncated) return;
            Object size = payload.get("byte_count");
            if (!"base64".equals(payload.get("encoding")) || !(size instanceof Long)
                    || (Long) size < 0 || !(payload.get("data") instanceof String)) {
                malformed = true;
                return;
            }
            try {
                byte[] part = Base64.getDecoder().decode((String) payload.get("data"));
                if ((Long) size != part.length) {
                    malformed = true;
                    return;
                }
                int count = budget.take(part.length);
                bytes.write(part, 0, count);
                truncated = count < part.length;
            } catch (IllegalArgumentException invalidBase64) {
                malformed = true;
            }
        }

        String text(boolean ended) {
            binary = false;
            if (malformed || bytes.size() == 0) return "";
            try {
                // Decode after concatenation, because process output chunks may
                // split a UTF-8 character. An unfinished trailing character is
                // retained until its next chunk, never shown as binary or �.
                CharsetDecoder decoder = StandardCharsets.UTF_8.newDecoder()
                        .onMalformedInput(CodingErrorAction.REPORT)
                        .onUnmappableCharacter(CodingErrorAction.REPORT);
                CharBuffer decoded = CharBuffer.allocate(bytes.size() + 1);
                boolean complete = ended && !truncated;
                CoderResult result = decoder.decode(ByteBuffer.wrap(bytes.toByteArray()), decoded, complete);
                if (result.isError()) result.throwException();
                if (complete) {
                    result = decoder.flush(decoded);
                    if (result.isError()) result.throwException();
                }
                String text = decoded.flip().toString();
                if (text.indexOf('\u0000') >= 0) {
                    binary = true;
                    return "";
                }
                return text;
            } catch (CharacterCodingException binaryOutput) {
                binary = true;
                return "";
            }
        }
    }
}
