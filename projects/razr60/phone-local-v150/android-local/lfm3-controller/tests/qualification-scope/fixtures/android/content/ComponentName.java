package android.content;
public final class ComponentName {final String pkg,name;public ComponentName(String p,String n){pkg=p;name=n;}public String getPackageName(){return pkg;}public String flattenToString(){return pkg+"/"+name;}}
