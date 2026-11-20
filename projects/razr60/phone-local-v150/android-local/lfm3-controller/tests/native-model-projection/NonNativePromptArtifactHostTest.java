package org.trillionnium.hepta.local;
import android.graphics.Rect;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.Collections;
import org.json.*;
/** Byte exports from actual ordinary/visual/Notes prompt paths. Host IO only. */
public final class NonNativePromptArtifactHostTest {
 private static Object call(Class<?> c,String n,Class<?>[] t,Object...a)throws Exception{Method m=c.getDeclaredMethod(n,t);m.setAccessible(true);return m.invoke(null,a);}
 private static Object field(Object o,String n)throws Exception{Field f=o.getClass().getDeclaredField(n);f.setAccessible(true);return f.get(o);}
 private static void set(Class<?> c,String n,Object o)throws Exception{Field f=c.getDeclaredField(n);f.setAccessible(true);f.set(null,o);}
 private static void write(Path p,String s)throws Exception{Files.write(p,s.getBytes(StandardCharsets.UTF_8));}
 private static void save(Path root,String name,Object f,LocalRuntimeConfig config)throws Exception{
  Path out=root.resolve(name);Files.createDirectories(out);if(field(f,"nativeDomain")!=null)throw new AssertionError("native domain in "+name);
  write(out.resolve("prompt.txt"),(String)field(f,"text"));
  write(out.resolve("system.txt"),(String)call(LocalTaskController.class,"systemPrompt",new Class<?>[]{LocalRuntimeConfig.class},config));
  write(out.resolve("grammar.gbnf"),((DecisionGrammar)field(f,"grammar")).text);
  Method b=f.getClass().getDeclaredMethod("budgetJson");b.setAccessible(true);write(out.resolve("budget.json"),((JSONObject)b.invoke(f)).toString());
  if(field(f,"visualPromptOriginal")!=null){Method e=f.getClass().getDeclaredMethod("visualPromptEvidence");e.setAccessible(true);write(out.resolve("source.json"),((JSONObject)e.invoke(f)).toString());}
 }

 private static Object ordinary(LocalRuntimeConfig config)throws Exception{
  String owner="查看当前读数；保留 <OWNER> 原文。",pkg="org.example.panel",task="11111111111111111111111111111111";
  PhoneObservation.Node node=new PhoneObservation.Node("n0",pkg,"android.widget.TextView","org.example:id/readout","当前读数 42","",
   new Rect(0,0,120,60),false,false,false,true,false,false,ObservedChildText.notApplicable(),ObservedScrollActions.UNKNOWN);
  int[] bounds={0,0,1080,2400};
  PhoneObservation phone=new PhoneObservation("22222222222222222222222222222222",pkg,100,1080,2400,0,7,
   new Rect(0,0,1080,2400),null,"a","b",new ObservationState("b",ImeVisibility.HIDDEN),
   ObservedWindowMetadata.observed(bounds,"android.widget.FrameLayout",1,0,bounds,"示例 <panel>"),false,Collections.singletonList(node));
  TaskAuthorization auth=TaskAuthorization.parse(owner);TaskAuthorization.Gate gate=auth.bind(task);
  TaskCompletionGate completion=new TaskCompletionGate(task,owner,auth);
  Object[] args={owner,new AppCatalogueRanker(Collections.singletonMap(pkg,"示例应用"),owner).search("",0),phone,new JSONArray(),
   null,null,null,config,new RepeatActionGuard(),new SameStateNoEffectGuard(),gate.frame(),null,null,completion,
   new NotesTaskPhaseGuard(task,auth),new CalculatorTaskInputGuard(task,auth)};
  for(Method m:LocalTaskController.class.getDeclaredMethods())if("prompt".equals(m.getName())&&m.getParameterTypes().length==args.length){m.setAccessible(true);return m.invoke(null,args);}
  throw new AssertionError("full controller prompt unavailable");
 }
 private static Object notes(Path fixture)throws Exception{
  byte[] bytes=Files.readAllBytes(fixture);
  if(!"160346f0506ccac079efc1b86c5f1ec957a7d01cbfa24a83e365ae5787cf5669".equals(MobiMindContract.sha(bytes)))throw new AssertionError("Notes fixture differs");
  Class<?> test=NotesTaskScopeHostTest.class;JSONObject files=new JSONObject(new String(bytes,StandardCharsets.UTF_8)).getJSONObject("files");set(test,"files",files);
  JSONObject ownerRecord=(JSONObject)call(test,"raw",new Class<?>[]{String.class},"owner.json");String owner=ownerRecord.getString("instruction");set(test,"owner",owner);
  JSONObject raw=(JSONObject)call(test,"raw",new Class<?>[]{String.class},"step-01-before.json");
  PhoneObservation phone=(PhoneObservation)call(test,"phone",new Class<?>[]{JSONObject.class},raw);
  NotesCompletionEvidence.Frame before=(NotesCompletionEvidence.Frame)call(test,"frame",new Class<?>[]{JSONObject.class},raw);
  TaskCompletionGate completion=(TaskCompletionGate)call(test,"gate",new Class<?>[]{});completion.observed(before);
  String task="3a086c73df614b87a0cfd3cc06710942";TaskAuthorization auth=TaskAuthorization.parse(owner);
  return call(test,"prompt",new Class<?>[]{String.class,PhoneObservation.class,TaskAuthorization.Gate.class,TaskCompletionGate.class,NotesTaskPhaseGuard.class,JSONArray.class,SameStateNoEffectGuard.class},
   owner,phone,auth.bind(task),completion,new NotesTaskPhaseGuard(task,auth),new JSONArray(),new SameStateNoEffectGuard());
 }

 public static void main(String[] a)throws Exception{
  Path out=Paths.get(a[0]);Files.createDirectories(out);
  LocalRuntimeConfig text=new LocalRuntimeConfig(ModelProfile.LFM3,"npu",8192,4),visual=new LocalRuntimeConfig(ModelProfile.GUI_OWL_4B,"npu",8192,4);
  save(out,"ordinary",ordinary(text),text);save(out,"visual",ordinary(visual),visual);save(out,"notes",notes(Paths.get(a[1])),text);
  System.out.println("{\"passed\":true,\"modes\":3,\"phone_operations\":0,\"model_inference\":false}");
 }
}
