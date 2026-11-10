package android.content.pm;
import android.content.*;
public final class PackageManager {
 public static final int MATCH_DEFAULT_ONLY=1;public final java.util.Map<String,PackageInfo> packages=new java.util.LinkedHashMap<String,PackageInfo>();
 public String homePackage="com.motorola.launcher3",homeClass="com.motorola.launcher3.Launcher",resolvedOverride;
 public PackageInfo getPackageInfo(String p,int flags){PackageInfo value=packages.get(p);if(value==null)throw new IllegalArgumentException("missing package "+p);return value;}
 public Intent getLaunchIntentForPackage(String p){return new Intent(Intent.ACTION_MAIN).setComponent(new ComponentName(p,p+".Main"));}
 public ResolveInfo resolveActivity(Intent i,int flags){ResolveInfo r=new ResolveInfo();r.activityInfo=new ActivityInfo();
  r.activityInfo.packageName=i.hasCategory(Intent.CATEGORY_HOME)?homePackage:(resolvedOverride==null?i.getComponent().getPackageName():resolvedOverride);
  r.activityInfo.name=i.hasCategory(Intent.CATEGORY_HOME)?homeClass:r.activityInfo.packageName+".Main";return r;}
}
