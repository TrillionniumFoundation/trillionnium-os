package org.trillionnium.hepta.local;
import java.nio.file.*;import java.lang.reflect.*;import org.json.*;
public final class ShoppingFooterStrictBaselineHost {
 public static void main(String[] args)throws Exception{
  JSONObject a=new JSONObject(Files.readString(Paths.get(args[0]))),b=new JSONObject(Files.readString(Paths.get(args[1])));
  if(WebShoppingObservationStability.supportsCaptures(a,b))throw new AssertionError("baseline incorrectly admitted footer change");
  Method m=WebShoppingObservationStability.class.getDeclaredMethod("captureDom",JSONObject.class,JSONObject.class);m.setAccessible(true);
  String reason=null;try{m.invoke(null,a,b);}catch(InvocationTargetException expected){reason=expected.getCause().getMessage();}
  if(reason==null||!reason.contains("non-recommendation semantic data changed"))throw new AssertionError("unexpected baseline rejection: "+reason);
  System.out.println(new JSONObject().put("schema","hepta.footer-strict-baseline-red.v1").put("expected_rejection",true)
   .put("reason",reason).put("phone_actions",0).put("business_verified",false).toString(2));
 }
}
