import org.trillionnium.hepta.local.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Synthetic input-boundary contracts; never model inference or screenshot-decoder proof. */
public final class UiVenusInputContractHostTest {
    static int assertions;
    static byte[] fixture,owner,prompt,system,image,source;
    interface Attempt {void run() throws Exception;}
    static void yes(boolean v){assertions++;if(!v)throw new AssertionError();}
    static void rejects(Attempt a)throws Exception{boolean rejected=false;try{a.run();}catch(IllegalArgumentException expected){rejected=true;}yes(rejected);}
    static UiVenusInputContract.Inputs verify(byte[] f,byte[] o,byte[] p,byte[] s,byte[] i,byte[] t)throws Exception{return UiVenusInputContract.verify(f,o,p,s,i,t);}
    public static void main(String[] args)throws Exception{
        Path p=Paths.get("tests/ui-venus");fixture=Files.readAllBytes(p.resolve("FIXTURE.json"));owner=Files.readAllBytes(p.resolve("owner.txt"));
        prompt=Files.readAllBytes(p.resolve("prompt.txt"));system=Files.readAllBytes(p.resolve("system.txt"));image=Files.readAllBytes(p.resolve("screen.png"));
        source=Files.readAllBytes(Paths.get("provenance/ui-venus-app-r1/official-system-template.txt"));
        UiVenusInputContract.Inputs actual=verify(fixture,owner,prompt,system,image,source);
        yes(actual.width==32&&actual.height==64&&actual.owner.equals(new String(owner,StandardCharsets.UTF_8)));
        byte[] snapshot=actual.image();snapshot[0]=0;yes(actual.image()[0]==(byte)137);
        byte[] saved=image.clone();image[0]=0;yes(actual.image()[0]==(byte)137);image=saved;
        rejects(() -> verify(fixture,"另一用户任务".getBytes(StandardCharsets.UTF_8),prompt,system,image,source));
        rejects(() -> verify(fixture,owner,"Current Screenshot:".getBytes(StandardCharsets.UTF_8),system,image,source));
        rejects(() -> verify(fixture,owner,prompt,Arrays.copyOf(system,system.length-1),image,source));
        rejects(() -> verify(fixture,owner,prompt,system,image,Arrays.copyOf(source,source.length-1)));
        rejects(() -> verify(fixture,new byte[4097],prompt,system,image,source));
        byte[] corrupt=image.clone();corrupt[32]^=1;rejects(() -> verify(fixture,owner,prompt,system,corrupt,source));
        byte[] changed=fixture.clone();String json=new String(changed,StandardCharsets.UTF_8);
        rejects(() -> verify(json.replace("mobile-first-frame-fixture.v1","mobile-first-frame-fixture.v2").getBytes(StandardCharsets.UTF_8),owner,prompt,system,image,source));
        rejects(() -> verify(json.replace("\"historical_turns\": 0","\"historical_turns\": 1").getBytes(StandardCharsets.UTF_8),owner,prompt,system,image,source));
        rejects(() -> verify(json.replace("\"max_tokens\": 1024","\"max_tokens\": 512").getBytes(StandardCharsets.UTF_8),owner,prompt,system,image,source));
        rejects(() -> verify(json.replace("\"image_bytes_unchanged\": true","\"image_bytes_unchanged\": false").getBytes(StandardCharsets.UTF_8),owner,prompt,system,image,source));
        rejects(() -> verify(json.replace("\"actions_dispatched\": false","\"actions_dispatched\": true").getBytes(StandardCharsets.UTF_8),owner,prompt,system,image,source));
        rejects(() -> verify(json.replace("\"n_img\": 0","\"n_img\": 1").getBytes(StandardCharsets.UTF_8),owner,prompt,system,image,source));
        yes(UiVenusPins.models()[0].bytes>Integer.MAX_VALUE);
        System.out.println("UI-Venus input contracts passed: "+assertions+"; synthetic headers only, no image decoding/inference");
    }
}
