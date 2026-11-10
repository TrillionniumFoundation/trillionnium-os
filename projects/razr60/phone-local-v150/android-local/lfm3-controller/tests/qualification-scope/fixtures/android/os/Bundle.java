package android.os;
public class Bundle {
 private final java.util.Map<String,Object> m=new java.util.HashMap<String,Object>();
 public void putString(String k,String v){m.put(k,v);}public String getString(String k){return (String)m.get(k);}
 public void putBoolean(String k,boolean v){m.put(k,v);}public boolean getBoolean(String k,boolean d){return m.containsKey(k)?(Boolean)m.get(k):d;}
 public void putCharSequence(String k,CharSequence v){m.put(k,v);}public CharSequence getCharSequence(String k){return (CharSequence)m.get(k);}
}
