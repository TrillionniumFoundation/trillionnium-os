package android.content;
public class Context {
    private final android.content.pm.ApplicationInfo info=new android.content.pm.ApplicationInfo();
    public Context getApplicationContext(){return this;}
    public android.content.pm.ApplicationInfo getApplicationInfo(){return info;}
}
