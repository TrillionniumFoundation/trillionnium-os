package android.content;
public class Intent {
 public static final String ACTION_MAIN="MAIN",CATEGORY_HOME="HOME",CATEGORY_LAUNCHER="LAUNCHER";public static final int FLAG_ACTIVITY_NEW_TASK=1,FLAG_ACTIVITY_CLEAR_TOP=2,FLAG_ACTIVITY_MULTIPLE_TASK=4;
 private String action,type,pkg;public int flags;private ComponentName component;private final java.util.Set<String> categories=new java.util.HashSet<String>();private final java.util.Map<String,Object> extras=new java.util.HashMap<String,Object>();
 public Intent(){}public Intent(String a){action=a;}public Intent addCategory(String c){categories.add(c);return this;}public boolean hasCategory(String c){return categories.contains(c);}public String getAction(){return action;}
 public Intent setComponent(ComponentName c){component=c;return this;}public ComponentName getComponent(){return component;}public Intent addFlags(int flags){this.flags|=flags;return this;}public Intent setPackage(String pkg){this.pkg=pkg;return this;}public String getPackage(){return pkg;}public Intent setType(String type){this.type=type;return this;}public String getType(){return type;}public int extraCount(){return extras.size();}
 public Intent putExtra(String k,String v){extras.put(k,v);return this;}public Intent putExtra(String k,boolean v){extras.put(k,v);return this;}public Intent putExtra(String k,int v){extras.put(k,v);return this;}
 public boolean hasExtra(String k){return extras.containsKey(k);}public String getStringExtra(String k){return (String)extras.get(k);}public boolean getBooleanExtra(String k,boolean d){return extras.containsKey(k)?(Boolean)extras.get(k):d;}public int getIntExtra(String k,int d){return extras.containsKey(k)?(Integer)extras.get(k):d;}public void removeExtra(String k){extras.remove(k);}
}
