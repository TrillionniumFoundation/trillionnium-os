package org.trillionnium.hepta.local;
import android.content.Context;import java.util.List;import org.trillionnium.hepta.background.ProfileTarget;
/** Explicit fail-only boundary; legacy host cases cannot start su, enumerate or qualify profiles. */
final class ProfileCatalogueClient {
 static List<ProfileTarget> load(Context context){throw new AssertionError("legacy host fixture has no profile catalogue");}
 static void requireCurrent(Context context,ProfileTarget expected){throw new AssertionError("legacy host fixture cannot qualify profile installation");}
}
