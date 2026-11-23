package org.trillionnium.hepta.local;

/** Unconstructible type-only planning boundary for old pure grammar suites.
 * No saved planning receipt, role or action authority can be produced here. */
final class NativeSearchPlanning {
    final String id=null,packageName=null;
    final Role role=null;
    private NativeSearchPlanning(){throw unavailable();}
    static final class Role {
        final String roleId=null;
        private Role(){throw unavailable();}
    }
    private static UnsupportedOperationException unavailable(){
        return new UnsupportedOperationException("Native search planning is not executed by legacy pure host suites");
    }
}
