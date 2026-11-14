package org.trillionnium.hepta.local;
import java.nio.file.Path;
import java.nio.file.Paths;

/** One new integration main; original pure comparator main has its own receipt. */
final class NativeActionIntegrationHostTest {
    public static void main(String[] args)throws Exception{
        Path source=Paths.get(args[0]),out=Paths.get(args[1]),scratch=Paths.get(args[2]);
        NativeActionSessionHostTest.run(source,scratch.resolve("home"));
        XiaomiActionGuardHost.run(source.resolve("tests/native-xiaomi-product/fixtures"));
        NativeActionBridgeHost.run(source);
        IntegrationChecks.finish(out,"hepta.native-action-integration-host.v1",
                "Actual Session and extracted Service bridge methods with complete synthetic census and explicit Android boundaries. Original provider/year roundtrip and Xiaomi XML factories reused; no phone, SDK, model, platform effect or business qualification.");
    }
}
