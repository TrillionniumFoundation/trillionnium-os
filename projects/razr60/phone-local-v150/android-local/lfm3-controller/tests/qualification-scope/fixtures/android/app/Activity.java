package android.app;
public class Activity {public static final String INPUT_METHOD_SERVICE="ime";protected void onSaveInstanceState(android.os.Bundle b){}public Object getSystemService(String s){return new android.view.inputmethod.InputMethodManager();}public boolean moveTaskToBack(boolean b){return true;}}
