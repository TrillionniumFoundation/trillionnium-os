package org.trillionnium.hepta.local;
/** Compiler shape only. No automatic-mode selection can be constructed. */
final class BackgroundAutoTargetResolver {
    private BackgroundAutoTargetResolver(){throw unavailable();}
    static final class StartSelection {
        final Entry entry=null;
        final NativeAppGoal nativeGoal=null;
        final String sha256=null;
        private StartSelection(){throw unavailable();}
        void requireOwner(String owner){throw unavailable();}
        java.util.Map<String,Object> evidence(){throw unavailable();}
    }
    static final class Entry {
        final Choice choice=null;
        private Entry(){throw unavailable();}
        String packageName(){throw unavailable();}
    }
    static final class Choice {
        final org.trillionnium.hepta.background.ProfileTarget profileTarget=null;
        private Choice(){throw unavailable();}
    }
    private static UnsupportedOperationException unavailable(){
        return new UnsupportedOperationException("Automatic target authority absent in original manual route cases");
    }
}
