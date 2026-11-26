package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import static org.trillionnium.hepta.local.VlmResultContractHostTest.*;

/** Real profile/config/receipt code; synthetic native receipts, zero model/phone execution. */
public final class Lfm3VlProfileHostTest {
    private static final VlmResultContract.Profile P=VlmResultContract.LFM3_VL_2B;
    private static int assertions;
    private static byte[] lfmTemplate;
    private interface Work {void run()throws Exception;}
    private interface Mutation {void run(F value)throws Exception;}
    private static void check(boolean value,String reason){assertions++;if(!value)throw new AssertionError(reason);}
    private static void rejects(Work work,String reason)throws Exception{
        try{work.run();throw new AssertionError(reason);}
        catch(IllegalArgumentException expected){assertions++;}
    }
    private static Map<String,Object> config(){
        Map<String,Object> value=new LinkedHashMap<>();
        value.put("schema","hepta.local-runtime.v3");value.put("model_profile","lfm3-vl-2b-qad-q4_0");
        value.put("compute","npu");value.put("context_tokens",8192);value.put("threads",4);value.put("visual_mode","observe");
        return value;
    }
    private static byte[] expectedFormatted(F f){
        String system=new String(f.inputs.get("system.txt"),StandardCharsets.UTF_8);
        return b("<|startoftext|>"+(system.isEmpty()?"":"<|im_start|>system\n"+system+"<|im_end|>\n")
                +"<|im_start|>user\n<__media__>"+new String(f.inputs.get("prompt.txt"),StandardCharsets.UTF_8)
                +"<|im_end|>\n<|im_start|>assistant\n<think></think>");
    }
    private static F fixture()throws Exception{
        F f=new F();f.request.put("profile",P.id);f.request();f.r.put("profile",P.id);
        f.r.put("model_filename",P.modelFilename);f.r.put("model_bytes",P.modelBytes);f.r.put("model_sha256",P.modelSha256);
        f.r.put("projector_filename",P.projectorFilename);f.r.put("projector_bytes",P.projectorBytes);f.r.put("projector_sha256",P.projectorSha256);
        f.r.put("architecture",P.architecture);f.r.put("tokenizer_pre",P.tokenizerPre);f.r.put("tokenizer_model",P.tokenizerModel);
        f.sidecars.put("gguf-chat-template.jinja",lfmTemplate.clone());f.r.put("chat_template_sha256",sha(lfmTemplate));
        f.r.put("chat_template_bytes",(long)lfmTemplate.length);
        formatted(f,expectedFormatted(f));f.seal();return f;
    }
    private static void formatted(F f,byte[] value){
        f.sidecars.put("formatted-prompt.txt",value);f.r.put("formatted_prompt_sha256",sha(value));
    }
    private static List<String> errors(F f){
        return VlmResultContract.verify(f.r,f.sidecars,f.expected(f.owner,f.taskOwner,WORKER_TICKS,NOW,GOOD,P),0);
    }
    private static void refused(String name,Mutation mutation)throws Exception{
        F f=fixture();mutation.run(f);f.seal();List<String> errors=errors(f);
        check(!errors.isEmpty(),name+" was accepted");
    }
    public static void main(String[] args)throws Exception{
        template=Files.readAllBytes(Paths.get(args[0]));lfmTemplate=Files.readAllBytes(Paths.get(args[1]));
        check(lfmTemplate.length==12129&&sha(lfmTemplate).equals("f45005c50cd2a97329722bf3a2dee9f16c04cdf825a589b280fb7e99e6827818"),"actual GGUF template pin");
        ModelProfile model=ModelProfile.named("lfm3-vl-2b-qad-q4_0");
        check(model==ModelProfile.LFM3_VL_2B&&model.visual(),"closed visual identity");
        check(model.fileName.equals("LFM3-VL-2B-QAD-Q4_0.gguf")&&model.bytes==1049615648L
                &&model.sha256.equals("621c455376cb96a20891697deb9975c6fb47dd5ea98ed3ad1f3b7e8f24f0b1e6"),"official VL language artifact");
        check(!model.sha256.equals(ModelProfile.LFM3.sha256)&&model.bytes!=ModelProfile.LFM3.bytes,"text LFM3 cannot substitute VL language weights");
        check(model.revision.equals("1add221a5ea6c047fcf1eaaf2d247939d7cf8849")&&model.minimumAvailableBytes==(4L<<30),"pinned revision and provisional RAM admission");
        check(model.visualDirectory().equals("lfm3-vl-model")&&ModelProfile.GUI_OWL_4B.visualDirectory().equals("gui-owl-model"),"separate closed visual directories");
        check(VlmResultContract.named(model.id)==P&&P.projectorFilename.equals("mmproj-LFM3-VL-2B-F16.gguf")
                &&P.projectorBytes==378996032L&&P.projectorSha256.equals("1d8e6e58eefc093e09d6332f081516e1ddbd5b35cfca7f35463fb270db230b1e"),"exact F16 projector only");
        check(LocalRuntimeConfig.defaults().profile==ModelProfile.LFM3&&!LocalRuntimeConfig.defaults().visualObservationOnly,"text default unchanged");
        LocalRuntimeConfig admitted=LocalRuntimeConfig.fromFields(config());
        check(admitted.profile==model&&admitted.visualObservationOnly&&admitted.expectedDevice().equals("HTP0"),"explicit observe config");
        rejects(()->new LocalRuntimeConfig(model,"npu",8192,4),"implicit tools constructor");
        LocalRuntimeConfig explicitTools=new LocalRuntimeConfig(model,"npu",8192,4,false);
        check(explicitTools.profile==model&&!explicitTools.visualObservationOnly
                &&explicitTools.compute.equals("npu")&&explicitTools.contextTokens==8192&&explicitTools.threads==4
                &&explicitTools.expectedDevice().equals("HTP0"),"explicit tools constructor keeps the closed visual tuple");
        Map<String,Object> toolsFields=config();toolsFields.put("visual_mode","tools");
        LocalRuntimeConfig toolsConfig=LocalRuntimeConfig.fromFields(toolsFields);
        check(toolsConfig.profile==model&&!toolsConfig.visualObservationOnly
                &&toolsConfig.compute.equals("npu")&&toolsConfig.contextTokens==8192&&toolsConfig.threads==4
                &&toolsConfig.expectedDevice().equals("HTP0"),"explicit v3 tools config keeps the closed visual tuple");
        for(String field:new String[]{"model_profile","visual_mode","schema","compute","context_tokens","threads"}){
            Map<String,Object> value=config();value.remove(field);
            rejects(()->LocalRuntimeConfig.fromFields(value),"missing config field "+field);
        }
        for(Object[] pair:new Object[][]{{"visual_mode","auto"},{"compute","gpu"},
                {"context_tokens",4096},{"threads",3},{"model_profile","../lfm3-vl-model"},{"schema","hepta.local-runtime.v2"},
                {"projector_sha256",P.projectorSha256}}){
            Map<String,Object> value=config();value.put((String)pair[0],pair[1]);
            rejects(()->LocalRuntimeConfig.fromFields(value),"forbidden config "+pair[0]+"="+pair[1]);
        }
        rejects(()->VlmResultContract.named(ModelProfile.LFM3.id),"text profile in VLM");
        rejects(()->ModelProfile.LFM3.visualDirectory(),"text directory conversion");
        check(!new LocalRuntimeConfig(ModelProfile.GUI_OWL_4B,"npu",8192,4,false).visualObservationOnly,"existing GUI tools config unchanged");
        F positive=fixture();check(errors(positive).isEmpty(),"bound LFM3-VL fixture "+errors(positive));
        F rawOpaque=fixture();raw(rawOpaque,b("观察到日期网格，但没有经过验证的可点击节点。"));rawOpaque.seal();
        check(errors(rawOpaque).isEmpty(),"raw observation must remain unparsed");
        refused("text-only LFM3 substituted",f->{f.r.put("model_filename",ModelProfile.LFM3.fileName);f.r.put("model_bytes",ModelProfile.LFM3.bytes);f.r.put("model_sha256",ModelProfile.LFM3.sha256);});
        refused("GUI projector substituted",f->{f.r.put("projector_filename",VlmResultContract.GUI_OWL_4B.projectorFilename);f.r.put("projector_sha256",VlmResultContract.GUI_OWL_4B.projectorSha256);});
        refused("Q8 projector is not F16 qualification",f->{f.r.put("projector_filename","mmproj-LFM3-VL-2B-Q8_0.gguf");f.r.put("projector_bytes",203031872L);f.r.put("projector_sha256","c5c5b58d544a18da919172d2d0368090ea1a4a351b6feb7f8a326a264a5918ab");});
        refused("missing projector filename",f->f.r.remove("projector_filename"));
        refused("missing projector SHA",f->f.r.remove("projector_sha256"));
        refused("wrong model byte hash",f->f.r.put("model_sha256",sha(b("foreign"))));
        refused("wrong same-size projector hash",f->f.r.put("projector_sha256",sha(b("foreign"))));
        refused("GUI template substituted",f->{f.sidecars.put("gguf-chat-template.jinja",template);f.r.put("chat_template_sha256",sha(template));f.r.put("chat_template_bytes",(long)template.length);});
        refused("missing BOS in rehashed prompt",f->formatted(f,b(new String(expectedFormatted(f),StandardCharsets.UTF_8).replace("<|startoftext|>",""))));
        refused("thinking enabled in rehashed prompt",f->formatted(f,b(new String(expectedFormatted(f),StandardCharsets.UTF_8).replace("<think></think>","<think>"))));
        refused("GUI formatting with LFM3 metadata",f->formatted(f,VlmResultContractHostTest.formatted(f.inputs)));
        refused("wrong architecture",f->f.r.put("architecture","qwen3vl"));
        refused("wrong tokenizer pre",f->f.r.put("tokenizer_pre","qwen2"));
        refused("wrong tokenizer model",f->f.r.put("tokenizer_model","llama"));
        refused("CPU language fallback",f->f.r.put("lm_device","CPU"));
        refused("CPU vision fallback",f->f.r.put("vision_device","CPU"));
        refused("different model request",f->{f.request.put("profile",VlmResultContract.GUI_OWL_4B.id);f.request();});
        refused("native action authority",f->f.r.put("action_authorized",true));
        refused("native dispatched action",f->f.r.put("actions_dispatched",true));
        refused("invented business completion",f->f.r.put("business_completion_verified",true));
        refused("image token overflow",f->counts(f,127,1025,9));
        F ui=fixture();rejects(()->ui.expected(ui.owner,ui.taskOwner,WORKER_TICKS,NOW,GOOD,VlmResultContract.UI_VENUS_9B),"unverified UI-Venus must stay blocked");
        Map<String,Object> report=new LinkedHashMap<>();report.put("schema","hepta.lfm3vl.profile-host.v1");report.put("all_pass",true);
        report.put("assertions",assertions);report.put("phone_operations",0);report.put("model_inference",false);
        report.put("native_receipts_synthetic",true);report.put("actions_dispatched",false);report.put("business_completion_verified",false);
        Files.write(Paths.get(args[2]),json(report));
        System.out.println("PASS "+assertions+" LFM3-VL profile/config/receipt assertions; no model/phone/action operation");
    }
}
