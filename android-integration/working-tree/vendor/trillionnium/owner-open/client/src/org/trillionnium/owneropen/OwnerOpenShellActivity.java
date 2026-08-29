package org.trillionnium.owneropen;

import android.app.Activity;
import android.os.Bundle;
import android.text.InputType;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import java.io.IOException;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Minimal truthful UI over the owner-open R5 broker wire. */
public final class OwnerOpenShellActivity extends Activity implements OwnerOpenClient.Listener {
    private final ExecutorService operations = Executors.newSingleThreadExecutor();
    private final String sessionId = id("session");
    private final String taskId = id("task");
    private OwnerOpenClient client;
    private String turnId;
    private EditText prompt;
    private TextView transcript;

    @Override
    protected void onCreate(Bundle state) {
        super.onCreate(state);
        client = new OwnerOpenClient(this);
        setContentView(buildView());
        runOperation("connect", () -> client.connect());
    }

    private LinearLayout buildView() {
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int padding = Math.round(16 * getResources().getDisplayMetrics().density);
        root.setPadding(padding, padding, padding, padding);

        prompt = new EditText(this);
        prompt.setHint(R.string.prompt_hint);
        prompt.setMinLines(3);
        prompt.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        root.addView(prompt, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        LinearLayout controls = new LinearLayout(this);
        controls.setOrientation(LinearLayout.HORIZONTAL);
        Button send = button(R.string.send, view -> sendPrompt());
        Button cancel = button(R.string.cancel, view -> cancelTurn());
        Button inspect = button(R.string.inspect, view -> inspectTurn());
        Button reconnect = button(R.string.reconnect, view -> reconnect());
        controls.addView(send);
        controls.addView(cancel);
        controls.addView(inspect);
        controls.addView(reconnect);
        root.addView(controls, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        transcript = new TextView(this);
        transcript.setTextIsSelectable(true);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(transcript, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));
        root.addView(scroll, new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, 0, 1));
        return root;
    }

    private Button button(int label, android.view.View.OnClickListener action) {
        Button result = new Button(this);
        result.setText(label);
        result.setOnClickListener(action);
        result.setAllCaps(false);
        result.setLayoutParams(new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1));
        return result;
    }

    private void sendPrompt() {
        String value = prompt.getText().toString();
        if (value.isBlank()) {
            append("local: prompt is empty");
            return;
        }
        String selectedTurn = id("turn");
        turnId = selectedTurn;
        runOperation("turn.start", () -> {
            ensureConnected();
            String request = client.startTurn(sessionId, taskId, selectedTurn, value);
            append("local request_id=" + request + " turn_id=" + selectedTurn);
        });
    }

    private void cancelTurn() {
        String selectedTurn = turnId;
        if (selectedTurn == null) {
            append("local: no turn has been started");
            return;
        }
        runOperation("turn.cancel", () -> {
            ensureConnected();
            append("local request_id=" + client.cancelTurn(sessionId, selectedTurn));
        });
    }

    private void inspectTurn() {
        String selectedTurn = turnId;
        if (selectedTurn == null) {
            append("local: no turn has been started");
            return;
        }
        runOperation("turn.inspect", () -> {
            ensureConnected();
            append("local request_id=" + client.inspectTurn(
                    sessionId, taskId, selectedTurn, 0));
        });
    }

    private void reconnect() {
        runOperation("reconnect", () -> {
            client.connect();
            append("local: reconnected");
        });
    }

    private void ensureConnected() throws IOException {
        if (!client.isConnected()) {
            client.connect();
        }
    }

    private void runOperation(String label, CheckedOperation operation) {
        operations.execute(() -> {
            try {
                operation.run();
            } catch (Exception error) {
                append("local " + label + " failed: " + error);
            }
        });
    }

    @Override
    public void onFrame(String rawJsonLine) {
        append(rawJsonLine);
    }

    @Override
    public void onDisconnected(String reason) {
        append("local disconnected: " + reason);
    }

    private void append(String value) {
        runOnUiThread(() -> transcript.append(value + "\n"));
    }

    private static String id(String prefix) {
        return prefix + "-" + UUID.randomUUID();
    }

    @Override
    protected void onDestroy() {
        client.shutdown();
        operations.shutdownNow();
        super.onDestroy();
    }

    @FunctionalInterface
    private interface CheckedOperation {
        void run() throws Exception;
    }
}
