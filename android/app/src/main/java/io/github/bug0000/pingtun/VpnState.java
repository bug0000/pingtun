package io.github.bug0000.pingtun;

final class VpnState {
    static volatile boolean running;
    static volatile String message = "Отключено";
    static volatile String detail = "Готов к подключению";
    static volatile String stats = "{}";
    private VpnState() {}
}
