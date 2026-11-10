package android.content;
import android.content.pm.PackageManager;import android.content.res.AssetManager;import java.io.File;
public class Context {private final File files;private final PackageManager pm;public Context(File f,PackageManager p){files=f;pm=p;}public File getFilesDir(){return files;}public PackageManager getPackageManager(){return pm;}public String getPackageName(){return "org.trillionnium.hepta.local";}public AssetManager getAssets(){return new AssetManager(new File(files,"assets"));}}
