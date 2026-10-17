package io.github.bug0000.pingtun;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.os.PowerManager;
import android.os.SystemClock;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import org.json.JSONArray;
import org.json.JSONObject;

public final class TunnelService extends VpnService {
    static final String STOP = "io.github.bug0000.pingtun.STOP";
    private final ScheduledThreadPoolExecutor worker = new ScheduledThreadPoolExecutor(1);
    private ParcelFileDescriptor tunnel;
    private String profile;
    private boolean engineActive;
    private boolean desired;
    private long lastAttempt;
    private PowerManager.WakeLock wake;
    private ConnectivityManager.NetworkCallback callback;
    private String notificationText = "";
    private int networkGeneration;
    private long lastReconnect;

    @Override public void onCreate() {
        super.onCreate();
        worker.setRemoveOnCancelPolicy(true);
        worker.setContinueExistingPeriodicTasksAfterShutdownPolicy(false);
        worker.setExecuteExistingDelayedTasksAfterShutdownPolicy(false);
        NotificationManager notifications = getSystemService(NotificationManager.class);
        notifications.createNotificationChannel(new NotificationChannel("vpn", "Соединение VPN", NotificationManager.IMPORTANCE_LOW));
        worker.scheduleWithFixedDelay(this::refresh, 1, 2, TimeUnit.SECONDS);
    }
    @Override public int onStartCommand(Intent intent, int flags, int startId) {
        if (intent != null && STOP.equals(intent.getAction())) {
            post(() -> { closeSession(); stopSelf(); }); return START_NOT_STICKY;
        }
        Notification notification = notification("Подключение…");
        if (Build.VERSION.SDK_INT >= 34) startForeground(1, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SYSTEM_EXEMPTED);
        else startForeground(1, notification);
        post(this::connect);
        return START_STICKY;
    }
    private Notification notification(String text) {
        PendingIntent open = PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        PendingIntent stop = PendingIntent.getService(this, 1, new Intent(this, TunnelService.class).setAction(STOP), PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
        return new Notification.Builder(this, "vpn").setSmallIcon(R.drawable.ic_status)
            .setContentTitle("pingtun").setContentText(text).setContentIntent(open).setOngoing(true)
            .addAction(new Notification.Action.Builder(null, "Отключить", stop).build()).build();
    }
    private void state(String title, String detail) {
        VpnState.message = title; VpnState.detail = detail;
        if (!title.equals(notificationText)) {
            notificationText = title;
            getSystemService(NotificationManager.class).notify(1, notification(title));
        }
    }
    @android.annotation.SuppressLint("WakelockTimeout") // Explicit user opt-in; released with the VPN session.
    private void connect() {
        if (desired) return;
        desired = true;
        try {
            if (VpnService.prepare(this) != null) throw new IllegalStateException("VPN permission required");
            profile = new ProfileStore(this).load();
            JSONObject info = new JSONObject(NativeEngine.inspect(profile));
            if (info.has("error")) throw new IllegalStateException("Invalid profile");
            String[] address = info.getString("address").split("/");
            Builder builder = new Builder().setSession("pingtun · " + info.getString("name"))
                .setMtu(info.getInt("mtu")).setBlocking(true)
                .addAddress(address[0], Integer.parseInt(address[1])).addRoute("0.0.0.0", 0)
                .addAddress("fd00:7069:6e67::2", 128).addRoute("::", 0);
            // IPv6 is deliberately captured and dropped by our IPv4-only engine.
            // Do not allow a separate IPv6 route to bypass the user's VPN choice.
            JSONArray dns = info.getJSONArray("dns");
            for (int i = 0; i < dns.length(); i++) builder.addDnsServer(dns.getString(i));
            tunnel = builder.establish();
            if (tunnel == null) throw new IllegalStateException("VPN permission revoked");
            VpnState.running = true;
            if (getSharedPreferences("ui", MODE_PRIVATE).getBoolean("awake", false)) {
                PowerManager power = getSystemService(PowerManager.class);
                wake = power.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "pingtun:connection");
                wake.setReferenceCounted(false); wake.acquire();
            }
            watchNetworks(); startEngine();
        } catch (Exception | LinkageError e) {
            if (tunnel == null) {
                closeSession(); VpnState.message = "Не удалось подключиться";
                VpnState.detail = "Проверьте профиль и разрешение на VPN"; stopSelf();
            } else state("Нет соединения", "Трафик приостановлен. Проверьте разрешение «Сеть» и доступность ICMP.");
        }
    }
    private void startEngine() {
        lastAttempt = SystemClock.elapsedRealtime();
        String error = NativeEngine.start(tunnel.getFd(), profile, this);
        engineActive = error == null;
        if (!engineActive) state("Нет соединения", "Трафик приостановлен. Проверьте разрешение «Сеть» и доступность ICMP.");
        else state("Подключение…", "Ожидаем защищённое соединение с сервером");
    }
    private void reconnect() {
        if (!desired || tunnel == null) return;
        NativeEngine.stop(); engineActive = false; startEngine();
    }
    private void refresh() {
        if (!desired || tunnel == null) return;
        try {
            if (!engineActive) {
                if (SystemClock.elapsedRealtime() - lastAttempt >= 10000) startEngine();
                return;
            }
            String raw = NativeEngine.snapshot();
            JSONObject stats = new JSONObject(raw); VpnState.stats = raw;
            if (stats.has("error")) { NativeEngine.stop(); engineActive = false; state("Восстановление…", "Трафик приостановлен до восстановления связи"); return; }
            long reply = stats.optLong("last_reply_unix");
            long now = stats.optLong("now_unix");
            if (stats.optLong("last_handshake_time_sec") > 0 && reply > 0 && now - reply <= 10)
                state("Подключено", "IPv4 через pingtun · IPv6 заблокирован");
            else state("Ожидание сервера", "Трафик приостановлен до установления защищённой связи");
        } catch (Exception | LinkageError e) { state("Нет соединения", "Трафик приостановлен. Можно отключить VPN и подключиться снова."); }
    }
    private void post(Runnable task) {
        try { if (!worker.isShutdown()) worker.execute(task); }
        catch (java.util.concurrent.RejectedExecutionException ignored) { /* Service is closing. */ }
    }
    private void networkChanged() {
        int generation = ++networkGeneration;
        worker.schedule(() -> {
            if (generation != networkGeneration || !desired || tunnel == null) return;
            try {
                JSONObject stats = new JSONObject(NativeEngine.snapshot());
                long age = System.currentTimeMillis() / 1000 - stats.optLong("last_reply_unix");
                // A protected, wildcard-bound datagram socket may follow the new
                // default network directly. Reopen only if replies did not resume.
                if (age <= 4 || SystemClock.elapsedRealtime() - lastReconnect < 15000) return;
                lastReconnect = SystemClock.elapsedRealtime(); reconnect();
            } catch (Exception | LinkageError ignored) { }
        }, 4, TimeUnit.SECONDS);
    }
    private void watchNetworks() {
        ConnectivityManager connectivity = getSystemService(ConnectivityManager.class);
        Set<Network> known = new HashSet<>();
        for (Network network : connectivity.getAllNetworks()) {
            NetworkCapabilities c = connectivity.getNetworkCapabilities(network);
            if (c != null && c.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) && c.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) known.add(network);
        }
        callback = new ConnectivityManager.NetworkCallback() {
            @Override public void onAvailable(Network network) { post(() -> { if (known.add(network)) networkChanged(); }); }
            @Override public void onLost(Network network) { post(() -> { if (known.remove(network)) networkChanged(); }); }
        };
        connectivity.registerNetworkCallback(new NetworkRequest.Builder().addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN).build(), callback);
    }
    private void closeSession() {
        boolean hadSession = desired || tunnel != null || engineActive;
        desired = false;
        if (callback != null) {
            try { getSystemService(ConnectivityManager.class).unregisterNetworkCallback(callback); }
            catch (IllegalArgumentException ignored) { }
            callback = null;
        }
        try { NativeEngine.stop(); } catch (LinkageError ignored) { }
        engineActive = false;
        if (tunnel != null) { try { tunnel.close(); } catch (java.io.IOException ignored) { } tunnel = null; }
        profile = null;
        if (wake != null) { if (wake.isHeld()) wake.release(); wake = null; }
        VpnState.running = false;
        if (hadSession) { VpnState.message = "Отключено"; VpnState.detail = "Обычное подключение к сети"; VpnState.stats = "{}"; }
        stopForeground(STOP_FOREGROUND_REMOVE);
    }
    @Override public void onRevoke() { post(() -> { closeSession(); stopSelf(); }); }
    @Override public void onDestroy() {
        post(this::closeSession); worker.shutdown(); super.onDestroy();
    }
}
