package org.trillionnium.hepta.local;
import android.view.accessibility.AccessibilityWindowInfo;import android.graphics.Rect;import android.os.*;import java.util.*;import java.nio.file.*;import java.nio.charset.StandardCharsets;
/** Runs the exact production consumer against explicit controlled platform values. */
public final class ParcelReaderHostTest {
 interface Check{void run();}static int assertions;static final List<String> names=new ArrayList<String>();
 static void yes(boolean v){assertions++;if(!v)throw new AssertionError();}
 static void test(String name,Check c){c.run();names.add(name);}
 static void refuse(AccessibilityWindowInfo w){boolean no=false;try{ProfileTaskReader.actualProfileAccessibilityTaskId(w);}catch(IllegalStateException expected){no=true;}yes(no);}
 public static void main(String[] args)throws Exception{
  test("reads_actual_serialized_task_without_expected_input",()->{AccessibilityWindowInfo w=new AccessibilityWindowInfo();w.task=845;yes(ProfileTaskReader.actualProfileAccessibilityTaskId(w)==845);});
  test("title_cannot_inject_task_or_user",()->{AccessibilityWindowInfo w=new AccessibilityWindowInfo();w.title="id=96, taskId=1, userId=0 ] [ taskId=3";w.task=700;yes(ProfileTaskReader.actualProfileAccessibilityTaskId(w)==700);});
  test("unsupported_platform_refuses",()->{Build.VERSION.SDK_INT=35;try{refuse(new AccessibilityWindowInfo());}finally{Build.VERSION.SDK_INT=36;}});
  test("main_display_refuses",()->{AccessibilityWindowInfo w=new AccessibilityWindowInfo();w.display=0;refuse(w);});
  test("non_application_refuses",()->{AccessibilityWindowInfo w=new AccessibilityWindowInfo();w.type=3;refuse(w);});
  test("invalid_actual_task_refuses",()->{AccessibilityWindowInfo w=new AccessibilityWindowInfo();w.task=0;refuse(w);w.task=-1;refuse(w);});
  test("public_header_mismatch_refuses",()->{AccessibilityWindowInfo w=new AccessibilityWindowInfo();w.wireId=97;refuse(w);w.wireId=-2;w.wireDisplay=16;refuse(w);});
  test("unknown_boolean_property_schema_refuses",()->{AccessibilityWindowInfo w=new AccessibilityWindowInfo();w.wireFlags=19;refuse(w);});
  test("parent_identity_malformed_refuses",()->{AccessibilityWindowInfo w=new AccessibilityWindowInfo();w.parent=w.id;refuse(w);w.parent=-3;refuse(w);});
  test("region_mismatch_and_empty_refuse",()->{AccessibilityWindowInfo w=new AccessibilityWindowInfo();w.wireBounds=new Rect(0,0,1223,2992);refuse(w);w.wireBounds=null;w.bounds=new Rect();refuse(w);});
  test("full_framework_parse_must_consume_all_bytes",()->{AccessibilityWindowInfo w=new AccessibilityWindowInfo();w.trailing=true;refuse(w);});
  test("roundtrip_must_preserve_full_bytes",()->{AccessibilityWindowInfo.mutateRoundTrip=true;try{refuse(new AccessibilityWindowInfo());}finally{AccessibilityWindowInfo.mutateRoundTrip=false;}});
  test("framework_parse_exception_stays_refused",()->{AccessibilityWindowInfo.throwCreator=true;try{refuse(new AccessibilityWindowInfo());}finally{AccessibilityWindowInfo.throwCreator=false;}});
  test("bounded_parcel_size",()->{AccessibilityWindowInfo w=new AccessibilityWindowInfo();char[] large=new char[66000];Arrays.fill(large,'x');w.title=new String(large);refuse(w);});
  test("all_owned_parcels_and_framework_copies_released",()->{yes(Parcel.obtained==Parcel.recycled);yes(AccessibilityWindowInfo.copied==AccessibilityWindowInfo.recycled);});
  StringBuilder out=new StringBuilder("{\"schema\":\"hepta.profile-parcel-consumer-host.v1\",\"all_pass\":true,\"phone_operations\":0,\"android_runtime\":false,\"actual_framework_serialization_tested\":false,\"cases\":"+names.size()+",\"assertions\":"+assertions+",\"names\":[");
  for(int i=0;i<names.size();i++){if(i>0)out.append(',');out.append('"').append(names.get(i)).append('"');}out.append("]}\n");Files.write(Paths.get(args[0]),out.toString().getBytes(StandardCharsets.UTF_8));System.out.print(out);
 }
}
