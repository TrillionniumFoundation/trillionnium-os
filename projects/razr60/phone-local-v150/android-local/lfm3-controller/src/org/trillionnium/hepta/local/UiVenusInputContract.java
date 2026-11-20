package org.trillionnium.hepta.local;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Map;
import java.util.zip.CRC32;

/** Exact official first-frame rendering. No page classification or action interpretation. */
public final class UiVenusInputContract {
    private UiVenusInputContract() {}
    public static final class Inputs {
        public final String owner,ownerSha,promptSha,systemSha,imageSha,fixtureSha;
        public final int width,height;
        private final byte[] prompt,system,image,fixture;
        private Inputs(String owner,byte[] prompt,byte[] system,byte[] image,byte[] fixture,int width,int height){
            this.owner=owner;ownerSha=sha(owner.getBytes(StandardCharsets.UTF_8));
            this.prompt=prompt.clone();this.system=system.clone();this.image=image.clone();this.fixture=fixture.clone();
            promptSha=sha(prompt);systemSha=sha(system);imageSha=sha(image);fixtureSha=sha(fixture);this.width=width;this.height=height;
        }
        public byte[] prompt(){return prompt.clone();} public byte[] system(){return system.clone();}
        public byte[] image(){return image.clone();} public byte[] fixture(){return fixture.clone();}
    }
    public static Inputs verify(byte[] fixture,byte[] owner,byte[] prompt,byte[] system,byte[] image,byte[] source)throws Exception{
        require(fixture!=null&&fixture.length>0&&fixture.length<=131072,"fixture bound");
        require(owner!=null&&owner.length>0&&owner.length<=4096,"original OWNER bound");
        String task=MobiMindContract.utf8(owner);require(task.indexOf('\0')<0,"OWNER contains NUL");
        // A role/media token is not ordinary task prose in this one-image first-frame interface.
        for(String reserved:new String[]{"<|im_start|>","<|im_end|>","<|vision_start|>","<|vision_end|>","<|image_pad|>"})
            require(!task.contains(reserved),"OWNER contains reserved model token");
        require(source!=null&&UiVenusPins.OFFICIAL_SYSTEM_SHA.equals(sha(source)),"official SYSTEM asset pin");
        String template=MobiMindContract.utf8(source);
        require(template.endsWith("{user_task}")&&template.indexOf("{user_task}")==template.lastIndexOf("{user_task}"),"official task placeholder");
        byte[] expected=(template.substring(0,template.length()-11)+task).getBytes(StandardCharsets.UTF_8);
        require(system!=null&&Arrays.equals(system,expected),"SYSTEM is not exact official prefix plus unchanged OWNER");
        require(prompt!=null&&Arrays.equals(prompt,"Current Screenshot:\n".getBytes(StandardCharsets.UTF_8)),"first-frame user prompt");
        int[] geometry=png(image);
        Map<String,Object> f=MobiMindContract.jsonObject(fixture);
        equal(f,"schema","hepta.ui-venus.mobile-first-frame-fixture.v1");
        equal(f,"official_repository","inclusionAI/UI-Venus");equal(f,"official_revision",UiVenusPins.OFFICIAL_REVISION);
        equal(f,"official_file","models/mobile/mobile_example.py");equal(f,"official_file_sha256",UiVenusPins.OFFICIAL_FILE_SHA);
        equal(f,"official_system_template_sha256",UiVenusPins.OFFICIAL_SYSTEM_SHA);
        equal(f,"model_repository",UiVenusPins.MODEL_REPO);equal(f,"model_revision",UiVenusPins.MODEL_REVISION);
        UiVenusPins.FilePin[] weights=UiVenusPins.models();pin(object(f,"model"),weights[0]);pin(object(f,"mmproj"),weights[1]);
        Map<String,Object> files=object(f,"files");
        require(files.keySet().equals(new java.util.HashSet<String>(Arrays.asList("owner.txt","prompt.txt","system.txt","screen.png"))),"fixture input membership");
        file(object(files,"owner.txt"),owner);file(object(files,"prompt.txt"),prompt);file(object(files,"system.txt"),system);file(object(files,"screen.png"),image);
        equal(f,"owner_bytes_unchanged",true);equal(f,"image_bytes_unchanged",true);
        equal(f,"history_policy","initial_frame_empty_history");number(f,"historical_turns",0);number(f,"n_img",0);
        equal(f,"n_img_zero_does_not_authorize_dropping_existing_assistant_history",true);
        Map<String,Object> im=object(f,"image");number(im,"width",geometry[0]);number(im,"height",geometry[1]);
        number(im,"bit_depth",8);number(im,"color_type",image[25]&255);equal(im,"resized_by_fixture",false);
        Map<String,Object> probe=object(f,"requested_probe");number(probe,"context_tokens",8192);number(probe,"max_tokens",1024);
        number(probe,"deadline_ms",300000);equal(probe,"enable_thinking",true);equal(probe,"speculative_decoding",false);number(probe,"seed",42);
        decimal(probe,"temperature",0.1);decimal(probe,"repetition_penalty",1.05);decimal(probe,"frequency_penalty",0.3);
        number(f,"official_mobile_reference_max_tokens",16384);equal(f,"output_budget_is_smaller_than_official_reference",true);
        for(String key:new String[]{"full_multimodal_token_admission_proven","phone_contacted","inference_performed","actions_dispatched","ordinary_app_qualified"})equal(f,key,false);
        equal(f,"old_or_new_recording_is_model_only",true);
        return new Inputs(task,prompt,system,image,fixture,geometry[0],geometry[1]);
    }
    static int[] png(byte[] image){
        require(image!=null&&image.length>=33&&image.length<=8*1024*1024,"bounded complete original PNG required");
        byte[] magic={(byte)137,80,78,71,13,10,26,10};require(Arrays.equals(Arrays.copyOf(image,8),magic),"PNG signature");
        require(be32(image,8)==13&&image[12]=='I'&&image[13]=='H'&&image[14]=='D'&&image[15]=='R',"PNG IHDR");
        CRC32 crc=new CRC32();crc.update(image,12,17);require(crc.getValue()==(be32(image,29)&0xffffffffL),"PNG IHDR CRC");
        int w=be32(image,16),h=be32(image,20);
        require(w>0&&w<=4096&&h>0&&h<=4096&&(long)w*h<=16777216L,"PNG dimensions");
        require(image[24]==8&&(image[25]==2||image[25]==6)&&image[26]==0&&image[27]==0&&image[28]==0,"PNG encoding envelope");
        return new int[]{w,h};
    }
    private static int be32(byte[] bytes,int at){return (bytes[at]&255)<<24|(bytes[at+1]&255)<<16|(bytes[at+2]&255)<<8|(bytes[at+3]&255);}
    static String sha(byte[] bytes){return MobiMindContract.sha(bytes);}
    static void require(boolean valid,String error){if(!valid)throw new IllegalArgumentException(error);}
    static void equal(Map<String,Object> m,String key,Object v){require(v.equals(m.get(key)),"binding differs: "+key);}
    static long integer(Object v){return v instanceof Integer||v instanceof Long?((Number)v).longValue():Long.MIN_VALUE;}
    static void number(Map<String,Object> m,String key,long v){require(integer(m.get(key))==v,"integer binding differs: "+key);}
    private static void decimal(Map<String,Object> m,String key,double v){Object actual=m.get(key);require(actual instanceof Double&&Double.compare((Double)actual,v)==0,"decimal binding differs: "+key);}
    static Map<String,Object> object(Map<String,Object> m,String key){require(m.get(key) instanceof Map,"object required: "+key);return MobiMindContract.object(m.get(key));}
    private static void pin(Map<String,Object> m,UiVenusPins.FilePin p){equal(m,"name",p.name);equal(m,"sha256",p.sha256);number(m,"bytes",p.bytes);}
    private static void file(Map<String,Object> m,byte[] data){number(m,"bytes",data.length);equal(m,"sha256",sha(data));}
}
