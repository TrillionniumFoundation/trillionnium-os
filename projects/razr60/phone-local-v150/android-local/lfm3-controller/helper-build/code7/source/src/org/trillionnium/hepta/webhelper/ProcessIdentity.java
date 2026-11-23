package org.trillionnium.hepta.webhelper;

import android.app.ActivityManager;
import android.app.Application;
import android.content.Context;
import android.os.Process;
import android.os.SystemClock;
import android.provider.Settings;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import org.json.JSONObject;
import org.trillionnium.hepta.webprotocol.WebEvidenceProtocol;

/** One non-PII token per actual helper process, registered before a lease can load a page. */
final class ProcessIdentity {
    private static ProcessIdentity instance;
    private final JSONObject value;

    static synchronized ProcessIdentity get(Context context) throws Exception {
        if (instance == null) instance = new ProcessIdentity(context.getApplicationContext());
        return instance;
    }

    private ProcessIdentity(Context context) throws Exception {
        String processName=Application.getProcessName();
        if (!WebEvidenceProtocol.HELPER_PACKAGE.equals(context.getPackageName())
                || !WebEvidenceProtocol.HELPER_PACKAGE.equals(processName))
            throw new IllegalStateException("unexpected helper process");
        int boot=Settings.Global.getInt(context.getContentResolver(),Settings.Global.BOOT_COUNT);
        if (boot<0) throw new IllegalStateException("boot count unavailable");
        byte[] random=new byte[32];new SecureRandom().nextBytes(random);
        byte[] summary=("hepta-webhelper-v2:"+hex(random)).getBytes(StandardCharsets.US_ASCII);
        boolean registered=false;Object failure=JSONObject.NULL;
        try {
            ActivityManager manager=context.getSystemService(ActivityManager.class);
            if (manager==null) throw new IllegalStateException("ActivityManager unavailable");
            manager.setProcessStateSummary(summary);
            registered=true;
        } catch (RuntimeException unavailable) {
            failure=unavailable.getClass().getName();
        }
        value=new JSONObject().put("schema","hepta.web-helper.process-identity.v1")
                .put("pid",Process.myPid()).put("uid",Process.myUid()).put("process_name",processName)
                .put("boot_count",boot).put("recorded_elapsed_ms",SystemClock.elapsedRealtime())
                .put("state_summary_hex",hex(summary)).put("state_summary_registered",registered)
                .put("state_summary_registration_error",failure);
    }

    JSONObject snapshot() throws Exception { return new JSONObject(value.toString()); }

    static String hex(byte[] value) {
        char[] out=new char[value.length*2];char[] digits="0123456789abcdef".toCharArray();
        for(int i=0;i<value.length;i++){out[i*2]=digits[(value[i]&255)>>>4];out[i*2+1]=digits[value[i]&15];}
        return new String(out);
    }
}
