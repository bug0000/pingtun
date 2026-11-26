package io.github.bug0000.pingtun;

final class VpnState {
    static volatile boolean running;
    static volatile int message = R.string.disconnected;
    static volatile int detail = R.string.ready;
    static volatile String stats = "{}";
    private VpnState() {}
}
