package io.github.bug0000.pingtun;

import android.net.VpnService;

final class NativeEngine {
    static { System.loadLibrary("pingtun"); }
    private NativeEngine() {}
    static synchronized native String start(int tunFd, String privateProfile, VpnService service);
    static synchronized native void stop();
    static synchronized native String snapshot();
    static native String inspect(String privateProfile);
    static native String probeSocket();
}
