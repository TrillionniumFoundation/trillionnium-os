package android.window;

/**
 * Compile-only descriptor header for the Android 16 boot-framework API.
 * This file and its class files MUST NOT be packaged in any application or DEX.
 * Source: frameworks/base 99b01a65cc4c104933788b3143285ab6bae65827.
 * Bodies deliberately fail; the runtime implementation must come from the boot loader.
 */
public abstract class WindowInfosListener {
    public WindowInfosListener() { throw new LinkageError("compile-only framework header"); }
    public abstract void onWindowInfosChanged(android.view.InputWindowHandle[] windows,
            DisplayInfo[] displays);
    public android.util.Pair<android.view.InputWindowHandle[], DisplayInfo[]> register() {
        throw new LinkageError("compile-only framework header");
    }
    public void unregister() { throw new LinkageError("compile-only framework header"); }
    public static final class DisplayInfo {
        private DisplayInfo() { throw new LinkageError("compile-only framework header"); }
    }
}
