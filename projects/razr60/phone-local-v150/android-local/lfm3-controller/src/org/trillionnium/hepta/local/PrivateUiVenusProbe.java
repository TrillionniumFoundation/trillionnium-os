package org.trillionnium.hepta.local;

import android.content.Context;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

/** One private first-frame VLM diagnostic. An Intent never supplies input or action authority. */
final class PrivateUiVenusProbe {
    final String id,nonceSha;
    final UiVenusInputContract.Inputs inputs;
    private PrivateUiVenusProbe(String id,String nonce,UiVenusInputContract.Inputs inputs){
        this.id=id;nonceSha=MobiMindContract.sha(nonce.getBytes(StandardCharsets.UTF_8));this.inputs=inputs;
    }
    static PrivateUiVenusProbe consume(Context context,String nonce)throws Exception{
        if(nonce==null||!nonce.matches("[0-9a-f]{64}"))throw new IOException("one-use UI-Venus nonce required");
        File files=context.getFilesDir().getCanonicalFile();MobiMindPrivateFiles.directory(files,false);
        MobiMindPrivateFiles.Read record=MobiMindPrivateFiles.read(new File(files,"ui-venus-probe-request.json"),8192,true);
        UiVenusRequestContract.Claim claim=UiVenusRequestContract.validate(record.bytes,nonce,System.currentTimeMillis());
        String id=claim.id,fixtureSha=claim.fixtureSha;
        File directory=new File(files,"ui-venus-probe-inputs/"+id);
        if(!directory.equals(directory.getCanonicalFile()))throw new IOException("private input directory aliases");
        MobiMindPrivateFiles.directory(directory,false);
        byte[] fixture=read(directory,"FIXTURE.json",131072);
        if(!fixtureSha.equals(MobiMindContract.sha(fixture)))throw new IOException("private fixture SHA mismatch");
        UiVenusInputContract.Inputs inputs=UiVenusInputContract.verify(fixture,read(directory,"owner.txt",4096),
            read(directory,"prompt.txt",65536),read(directory,"system.txt",65536),read(directory,"screen.png",8*1024*1024),
            read(directory,"official-system-template.txt",65536));
        PrivateUiVenusProbe result=new PrivateUiVenusProbe(id,nonce,inputs);
        File claims=MobiMindPrivateFiles.directory(new File(files,"ui-venus-probe-consumed"),false);
        claim.requireFresh(System.currentTimeMillis());
        // Never remove an old claim or reuse a nonce after an acknowledgement/publication error.
        UiVenusRequestContract.commitClaim(record.bytes,new UiVenusRequestContract.ClaimStorage(){
            public void verifyOriginal()throws Exception{record.unchangedPath();}
            public void createExclusiveClaim(byte[] bytes)throws Exception{MobiMindPrivateFiles.writeNew(new File(claims,result.nonceSha+".json"),bytes);}
            public void removeOriginal()throws Exception{if(!record.path.delete())throw new IOException("claimed request could not be removed");}
            public void syncParent()throws Exception{MobiMindPrivateFiles.syncDirectory(files);}
        });return result;
    }
    private static byte[] read(File directory,String name,int limit)throws Exception{return MobiMindPrivateFiles.read(new File(directory,name),limit,true).bytes;}
}
