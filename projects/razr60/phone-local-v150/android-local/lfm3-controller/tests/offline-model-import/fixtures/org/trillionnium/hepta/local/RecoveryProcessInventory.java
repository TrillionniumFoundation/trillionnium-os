package org.trillionnium.hepta.local;
final class RecoveryProcessInventory {
    static java.util.List<RecoveryQuiescence.Sample> awaitInitial(LocalProbeApplication app){
        return java.util.Arrays.asList(new RecoveryQuiescence.Sample(),new RecoveryQuiescence.Sample());
    }
    static RecoveryQuiescence.Sample capture(LocalProbeApplication app){return new RecoveryQuiescence.Sample();}
}

