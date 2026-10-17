package io.github.bug0000.pingtun;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.json.JSONObject;

public final class MainActivity extends Activity {
    private final Handler main = new Handler(Looper.getMainLooper());
    private final ExecutorService files = Executors.newSingleThreadExecutor();
    private TextView profile, status, detail, counters;
    private Button connect, importer;
    private Switch awake;
    private boolean haveProfile;
    private final Runnable refresh = new Runnable() { public void run() { render(); main.postDelayed(this, 1000); } };
    private int dp(int n) { return (int)(getResources().getDisplayMetrics().density * n); }
    private TextView label(LinearLayout parent, String text, int size, boolean bold) {
        TextView v = new TextView(this); v.setText(text); v.setTextSize(size); v.setTextColor(Color.rgb(24, 43, 49));
        if (bold) v.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        v.setPadding(0, dp(10), 0, dp(10)); parent.addView(v); return v;
    }
    private Button button(LinearLayout parent, String text) {
        Button v = new Button(this); v.setText(text); v.setAllCaps(false); v.setTextSize(17); v.setMinHeight(dp(54));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2); lp.topMargin = dp(12); parent.addView(v, lp); return v;
    }
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        ScrollView scroll = new ScrollView(this); scroll.setFillViewport(true); scroll.setBackgroundColor(Color.rgb(245, 248, 249));
        LinearLayout body = new LinearLayout(this); body.setOrientation(LinearLayout.VERTICAL); body.setPadding(dp(24), dp(24), dp(24), dp(24));
        // Target 36 uses edge-to-edge; apply system insets without hiding controls.
        body.setOnApplyWindowInsetsListener((view, insets) -> {
            if (Build.VERSION.SDK_INT >= 30) {
                android.graphics.Insets bars = insets.getInsets(android.view.WindowInsets.Type.systemBars());
                view.setPadding(dp(24) + bars.left, dp(16) + bars.top, dp(24) + bars.right, dp(24) + bars.bottom);
            } else view.setPadding(dp(24) + insets.getSystemWindowInsetLeft(), dp(16) + insets.getSystemWindowInsetTop(), dp(24) + insets.getSystemWindowInsetRight(), dp(24) + insets.getSystemWindowInsetBottom());
            return insets;
        });
        scroll.addView(body); setContentView(scroll);
        label(body, "pingtun", 34, true); label(body, "Экспериментальный ICMP VPN", 16, false);
        profile = label(body, "Профиль не выбран", 19, true);
        status = label(body, "Отключено", 27, true); detail = label(body, "", 15, false);
        counters = label(body, "", 14, false);
        connect = button(body, "Подключить"); connect.setBackgroundTintList(ColorStateList.valueOf(Color.rgb(0, 107, 101))); connect.setTextColor(Color.WHITE);
        connect.setOnClickListener(v -> {
            if (VpnState.running) startService(new Intent(this, TunnelService.class).setAction(TunnelService.STOP));
            else if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
                requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 42);
            else prepareVpn();
        });
        importer = button(body, "Импортировать профиль"); importer.setOnClickListener(v -> startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT)
            .addCategory(Intent.CATEGORY_OPENABLE).setType("*/*"), 43));
        awake = new Switch(this); awake.setText("Поддерживать связь при выключенном экране"); awake.setTextSize(15); awake.setPadding(0, dp(22), 0, dp(12));
        awake.setChecked(getSharedPreferences("ui", MODE_PRIVATE).getBoolean("awake", false));
        awake.setOnCheckedChangeListener((v, checked) -> getSharedPreferences("ui", MODE_PRIVATE).edit().putBoolean("awake", checked).apply()); body.addView(awake);
        label(body, "Этот режим повышает расход батареи. Без него фоновая связь может задерживаться в режиме сна.", 13, false);
        label(body, "При потере сервера VPN удерживает трафик до восстановления связи. Для защиты при остановке приложения включите системное «Блокировать подключения без VPN».", 13, false);
        loadProfile();
    }
    private void loadProfile() {
        if (files.isShutdown()) return;
        files.execute(() -> {
            try {
                ProfileStore store = new ProfileStore(this);
                if (!store.exists()) return;
                JSONObject info = new JSONObject(NativeEngine.inspect(store.load()));
                if (info.has("error")) throw new IllegalStateException();
                String name = info.getString("name"); String endpoint = info.getString("server_ip");
                main.post(() -> { if (isDestroyed()) return; haveProfile = true; profile.setText(name + "\n" + endpoint); render(); });
            } catch (Exception | LinkageError e) { main.post(() -> { if (!isDestroyed()) profile.setText("Профиль недоступен. Импортируйте его снова."); }); }
        });
    }
    private void prepareVpn() {
        Intent prepare = VpnService.prepare(this);
        if (prepare != null) startActivityForResult(prepare, 44); else startForegroundService(new Intent(this, TunnelService.class));
    }
    @Override public void onRequestPermissionsResult(int request, String[] permissions, int[] grants) {
        super.onRequestPermissionsResult(request, permissions, grants); if (request == 42) prepareVpn();
    }
    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (request == 44 && result == RESULT_OK) startForegroundService(new Intent(this, TunnelService.class));
        if (request == 43 && result == RESULT_OK && data != null && data.getData() != null) {
            if (VpnState.running) return;
            files.execute(() -> {
                try (InputStream in = getContentResolver().openInputStream(data.getData())) {
                    if (in == null) throw new java.io.IOException();
                    String value = new String(ProfileStore.readBounded(in, 65536), StandardCharsets.UTF_8);
                    new ProfileStore(this).save(value); main.post(() -> { if (!isDestroyed()) loadProfile(); });
                } catch (Exception | LinkageError e) { main.post(() -> { if (!isDestroyed() && !isFinishing()) new android.app.AlertDialog.Builder(this).setTitle("Профиль не импортирован")
                    .setMessage("Нужен мобильный профиль pingtun, созданный отдельно для этого устройства.").setPositiveButton("Понятно", null).show(); }); }
            });
        }
    }
    private void render() {
        status.setText(VpnState.message); detail.setText(VpnState.detail);
        connect.setEnabled(haveProfile || VpnState.running); connect.setText(VpnState.running ? "Отключить" : "Подключить");
        importer.setEnabled(!VpnState.running); awake.setEnabled(!VpnState.running);
        try {
            JSONObject s = new JSONObject(VpnState.stats);
            if (VpnState.running && s.has("rtt_us")) counters.setText(String.format(java.util.Locale.getDefault(), "Задержка %.0f мс · Получено %.2f МБ · Отправлено %.2f МБ", s.optLong("rtt_us") / 1000.0, s.optLong("rx_bytes") / 1000000.0, s.optLong("tx_bytes") / 1000000.0));
            else counters.setText("");
        } catch (Exception ignored) { counters.setText(""); }
    }
    @Override protected void onResume() { super.onResume(); main.post(refresh); }
    @Override protected void onPause() { main.removeCallbacks(refresh); super.onPause(); }
    @Override protected void onDestroy() { main.removeCallbacksAndMessages(null); files.shutdown(); super.onDestroy(); }
}
