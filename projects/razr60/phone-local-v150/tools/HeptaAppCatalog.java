import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.os.Looper;
import org.json.JSONArray;
import org.json.JSONObject;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Read-only launcher catalog. Run through app_process; never launches an app. */
public final class HeptaAppCatalog {
    public static void main(String[] args) throws Exception {
        if (args.length != 0) throw new IllegalArgumentException("No arguments accepted");
        if (Looper.myLooper() == null) Looper.prepareMainLooper();
        Class<?> activityThread = Class.forName("android.app.ActivityThread");
        Method systemMain = activityThread.getDeclaredMethod("systemMain");
        Object thread = systemMain.invoke(null);
        Context context = (Context) activityThread.getDeclaredMethod("getSystemContext").invoke(thread);
        PackageManager pm = context.getPackageManager();
        Intent launcher = new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER);
        List<ResolveInfo> resolved = pm.queryIntentActivities(launcher, 0);
        List<JSONObject> rows = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (ResolveInfo result : resolved) {
            ActivityInfo info = result.activityInfo;
            if (info == null || !info.enabled || !info.exported || !info.applicationInfo.enabled) continue;
            String component = new ComponentName(info.packageName, info.name).flattenToShortString();
            if (!seen.add(component)) continue;
            CharSequence display = result.loadLabel(pm);
            String label = display == null ? info.packageName : display.toString().trim();
            if (label.isEmpty() || label.indexOf('\0') >= 0 || label.getBytes(StandardCharsets.UTF_8).length > 128)
                label = info.packageName;
            JSONObject row = new JSONObject();
            row.put("component", component);
            row.put("label", label);
            row.put("package", info.packageName);
            row.put("enabled", true);
            row.put("exported", true);
            rows.add(row);
        }
        rows.sort(Comparator.comparing(row -> row.optString("component")));
        JSONArray entries = new JSONArray();
        for (JSONObject row : rows) entries.put(row);
        JSONObject output = new JSONObject();
        output.put("schema", "hepta.local-launcher-catalog.v1");
        output.put("source", "on-phone PackageManager ACTION_MAIN CATEGORY_LAUNCHER");
        output.put("read_only", true);
        output.put("user_id", android.os.Process.myUid() / 100000);
        output.put("entry_count", entries.length());
        output.put("entries", entries);
        System.out.println(output.toString());
    }
}
