package android.content;import java.io.File;import android.os.IBinder;
public class Context {public static final int BIND_AUTO_CREATE=1;private final File files;public IBinder fixturePeer;
 public Context(File f){files=f;}public Context getApplicationContext(){return this;}public File getFilesDir(){return files;}
 public boolean bindService(Intent intent,ServiceConnection c,int flags){if(fixturePeer==null)return false;c.onServiceConnected(intent.component,fixturePeer);return true;}public void unbindService(ServiceConnection c){}
}