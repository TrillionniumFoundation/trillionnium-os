package org.trillionnium.hepta.controlprobe;

import android.app.Activity;
import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/** An ordinary editable field. No IME/service/permission/clipboard integration. */
public final class TextEntryActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        setTitle("HEPTA 中文输入验证");
        LinearLayout root = ProbeUi.column(this);
        root.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS);
        root.addView(ProbeUi.text(this, "中文直接输入验证", 25));
        root.addView(ProbeUi.text(this, "输入框使用系统标准 EditText；确认后在下方原样读回。", 16));
        EditText input = new EditText(this);
        input.setId(R.id.unicode_input);
        input.setHint("在此输入中文");
        input.setTextSize(19);
        input.setSingleLine(false);
        input.setMinLines(3);
        input.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_MULTI_LINE);
        root.addView(input, new LinearLayout.LayoutParams(-1, -2));
        Button submit = new Button(this);
        submit.setId(R.id.unicode_submit);
        submit.setText("确认并读回");
        root.addView(submit, new LinearLayout.LayoutParams(-1, -2));
        TextView readback = ProbeUi.text(this, "", 19);
        readback.setId(R.id.unicode_readback);
        readback.setTextIsSelectable(true);
        root.addView(readback, new LinearLayout.LayoutParams(-1, -2));
        TextView receipt = ProbeUi.text(this, "等待输入", 14);
        receipt.setId(R.id.unicode_receipt);
        root.addView(receipt, new LinearLayout.LayoutParams(-1, -2));
        submit.setOnClickListener(new View.OnClickListener() {
          @Override public void onClick(View view) {
            String value = input.getText().toString();
            readback.setText(value);
            if (value.isEmpty()) {
                receipt.setText("HEPTA_UNICODE_EMPTY");
            } else {
                receipt.setText("HEPTA_UNICODE_READBACK\nsha256=" + ProbeUi.sha256(value)
                        + "\ncodepoints=" + value.codePointCount(0, value.length())
                        + "\nutf8_bytes=" + value.getBytes(java.nio.charset.StandardCharsets.UTF_8).length);
            }
            InputMethodManager keyboard = (InputMethodManager) getSystemService(INPUT_METHOD_SERVICE);
            if (keyboard != null) keyboard.hideSoftInputFromWindow(input.getWindowToken(), 0);
          }
        });
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.addView(root);
        setContentView(scroll);
        // No Intent text/extras are accepted; only real UI edits can supply input.
    }
}
