package org.trillionnium.hepta.local;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Map;
import org.json.JSONObject;

/** Invoke the real controller prompt over the existing explicit native fixture.
 * The surrounding fixture supplies Android IO only; no phone or model is run. */
public final class NativeModelPromptWiringHostTest {
    private static int checks;
    private static void check(boolean ok,String why){checks++;if(!ok)throw new AssertionError(why);}
    private static Object invoke(Method method,Object target,Object...args)throws Exception{
        method.setAccessible(true);try{return method.invoke(target,args);}catch(InvocationTargetException error){
            if(error.getCause() instanceof Exception)throw (Exception)error.getCause();
            if(error.getCause() instanceof Error)throw (Error)error.getCause();throw error;
        }
    }
    private static Object field(Object target,String name)throws Exception{
        Field field=target.getClass().getDeclaredField(name);field.setAccessible(true);return field.get(target);
    }
    private static Map<String,Object> object(String text)throws Exception{return MobiMindContract.jsonObject(text.getBytes(StandardCharsets.UTF_8));}
    public static void main(String[] args)throws Exception{
        Class<?> fixture=Class.forName("org.trillionnium.hepta.local.NativeTerminalStatusHostTest");
        Class<?> context=Class.forName("org.trillionnium.hepta.local.NativeTerminalStatusHostTest$Context");
        Constructor<?> constructor=context.getDeclaredConstructor();constructor.setAccessible(true);Object c=constructor.newInstance();
        Method prompt=fixture.getDeclaredMethod("prompt",context,boolean.class);
        LocalRuntimeConfig config=new LocalRuntimeConfig(ModelProfile.LFM3,"npu",8192,4);
        String nativeSystem=(String)invoke(LocalTaskController.class.getDeclaredMethod("systemPrompt",LocalRuntimeConfig.class,boolean.class),null,config,true);
        String ordinarySystem=(String)invoke(LocalTaskController.class.getDeclaredMethod("systemPrompt",LocalRuntimeConfig.class),null,config);
        check(nativeSystem.equals(VisualPromptProjection.NATIVE_SYSTEM),"native system not selected from typed native domain");
        check(!nativeSystem.equals(ordinarySystem),"ordinary task system unexpectedly replaced");
        for(boolean fixed:new boolean[]{false,true}){
            Object frame=invoke(prompt,null,c,fixed);
            String text=(String)field(frame,"text");JSONObject full=(JSONObject)field(frame,"visualPromptOriginal");
            check(full!=null&&full.getJSONObject("task_authorization").has("authorization_sha256"),"full private authority not retained");
            int boundary=text.lastIndexOf("\nOWNER\n");check(text.startsWith("UNTRUSTED_DATA\n")&&boundary>0,"owner envelope changed");
            JSONObject shown=new JSONObject(text.substring("UNTRUSTED_DATA\n".length(),boundary));
            check(object(shown.toString()).equals(object(VisualPromptProjection.projectNative(full).toString())),"actual controller did not use complete native projection");
            check(object(full.getJSONObject("screen").toString()).equals(object(shown.getJSONObject("screen").toString())),"actual current screen changed");
            check(full.getJSONArray("events").toString().equals(shown.getJSONArray("events").toString()),"actual event history changed");
            JSONObject evidence=(JSONObject)invoke(frame.getClass().getDeclaredMethod("visualPromptEvidence",String.class),frame,VisualPromptProjection.NATIVE_SCHEMA);
            check(VisualPromptProjection.NATIVE_SCHEMA.equals(evidence.getString("schema")),"native evidence schema absent");
            check(object(full.toString()).equals(object(evidence.getJSONObject("original_controller_data").toString())),"private controller evidence altered");
            check(MobiMindContract.sha(text.getBytes(StandardCharsets.UTF_8)).equals(evidence.getString("model_prompt_sha256")),"actual projected prompt hash not bound");
            check(!evidence.getBoolean("grammar_or_dispatch_authority_changed"),"projection claimed new authority");
            DecisionGrammar grammar=(DecisionGrammar)field(frame,"grammar");
            check(grammar.text.contains("\\\"failure\\\"")&&!grammar.text.contains("\\\"partial\\\"")&&!grammar.successAllowed,
                    "actual native login terminal grammar widened");
            NativeAppDomain domain=(NativeAppDomain)field(frame,"nativeDomain");
            check(NativeXiaomiProductPage.LOGIN.equals(domain.phase),"actual existing login domain replaced");
        }
        JSONObject report=new JSONObject().put("schema","hepta.native-model-prompt-wiring-host.v1").put("passed",true).put("checks",checks)
                .put("phone_operations",0).put("model_inference",false).put("business_verified",false);
        Files.write(Paths.get(args[0]),(report.toString(2)+"\n").getBytes(StandardCharsets.UTF_8));System.out.println(report.toString());
    }
}
