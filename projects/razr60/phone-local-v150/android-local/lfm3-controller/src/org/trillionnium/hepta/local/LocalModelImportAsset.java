package org.trillionnium.hepta.local;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/** The same five profiles exposed by ordinary local-model settings; no caller-supplied path or pin. */
final class LocalModelImportAsset {
    final String label;
    final LocalModelImportFile.Pin pin;
    private LocalModelImportAsset(ModelProfile model,boolean projector){
        String directory=model.visual()?model.visualDirectory():"model";
        if(projector){
            VlmResultContract.Profile visual=VlmResultContract.named(model.id);
            label=model.displayName+" · 图像投影文件";
            pin=new LocalModelImportFile.Pin(model.id+"/projector",directory,visual.projectorFilename,
                    visual.projectorBytes,visual.projectorSha256);
        }else{
            label=model.displayName+" · 模型文件";
            pin=new LocalModelImportFile.Pin(model.id+"/model",directory,model.fileName,model.bytes,model.sha256);
        }
    }
    private static final List<LocalModelImportAsset> ALL=Collections.unmodifiableList(Arrays.asList(
            new LocalModelImportAsset(ModelProfile.LFM3,false),
            new LocalModelImportAsset(ModelProfile.LFM25_8B_A1B,false),
            new LocalModelImportAsset(ModelProfile.GUI_OWL_4B,false),
            new LocalModelImportAsset(ModelProfile.GUI_OWL_4B,true),
            new LocalModelImportAsset(ModelProfile.LFM3_VL_2B,false),
            new LocalModelImportAsset(ModelProfile.LFM3_VL_2B,true),
            new LocalModelImportAsset(ModelProfile.QWEN35_4B,false)));
    static List<LocalModelImportAsset> all(){return ALL;}
    static LocalModelImportAsset named(String id){
        for(LocalModelImportAsset value:ALL)if(value.pin.id.equals(id))return value;
        throw new IllegalArgumentException("请选择支持的本地模型文件");
    }
}

