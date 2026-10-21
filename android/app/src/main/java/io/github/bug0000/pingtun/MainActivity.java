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
    private TextView profile, endpoint, status, detail, action, rx, tx, latency;
    private Button connect, importer, settings;
    private boolean haveProfile;
    private final Runnable refresh = new Runnable() { public void run() { render(); main.postDelayed(this, 1000); } };
    private int dp(int n) { return Ui.dp(this, n); }
    private TextView centered(String value, int size, int color, boolean bold) {
        TextView t = Ui.text(this, value, size, color, bold); t.setGravity(android.view.Gravity.CENTER); return t;
    }
    private TextView metric(LinearLayout row, String title) {
        LinearLayout col = Ui.column(this); col.setGravity(android.view.Gravity.CENTER);
        TextView value = centered("—", 20, Ui.TEXT, true); col.addView(value);
        TextView caption = centered(title, 12, Ui.MUTED, false);
        LinearLayout.LayoutParams cp = new LinearLayout.LayoutParams(-1, -2); cp.topMargin = dp(8); col.addView(caption, cp);
        row.addView(col, new LinearLayout.LayoutParams(0, -2, 1)); return value;
    }
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        ScrollView scroll = new ScrollView(this); scroll.setFillViewport(true); scroll.setBackgroundColor(Ui.BG);
        LinearLayout body = Ui.column(this); scroll.addView(body); setContentView(scroll); Ui.insets(this, body);
        LinearLayout header = new LinearLayout(this); header.setGravity(android.view.Gravity.CENTER_VERTICAL);
        android.widget.ImageView mark = new android.widget.ImageView(this); mark.setImageResource(R.drawable.ic_launcher);
        mark.setImportantForAccessibility(View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        header.addView(mark, new LinearLayout.LayoutParams(dp(38), dp(38)));
        TextView brand = Ui.text(this, "pingtun", 25, Ui.TEXT, true);
        LinearLayout.LayoutParams bp = new LinearLayout.LayoutParams(0, -2, 1); bp.leftMargin = dp(12); header.addView(brand, bp);
        Button about = Ui.button(this, "О приложении", false); about.setTextSize(13);
        about.setOnClickListener(v -> startActivity(new Intent(this, AboutActivity.class))); header.addView(about);
        Ui.add(this, body, header, 0);
        Ui.add(this, body, centered("ВАШ ЛИЧНЫЙ ТУННЕЛЬ", 11, Ui.ACCENT, true), 46);
        status = centered("Отключено", 30, Ui.TEXT, true); status.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE); Ui.add(this, body, status, 15);
        detail = centered("Добавьте профиль, чтобы начать", 14, Ui.MUTED, false); Ui.add(this, body, detail, 12);
        connect = new PowerButton(this);
        LinearLayout.LayoutParams powerParams = new LinearLayout.LayoutParams(dp(176), dp(176)); powerParams.gravity = android.view.Gravity.CENTER_HORIZONTAL; powerParams.topMargin = dp(32); body.addView(connect, powerParams);
        connect.setOnClickListener(v -> {
            if (VpnState.running) startService(new Intent(this, TunnelService.class).setAction(TunnelService.STOP));
            else if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED)
                requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS}, 42);
            else prepareVpn();
        });
        action = centered("Подключить", 16, Ui.TEXT, true); Ui.add(this, body, action, 18);
        LinearLayout metrics = new LinearLayout(this); metrics.setPadding(dp(8), dp(22), dp(8), dp(22)); metrics.setBackground(Ui.shape(this, Ui.CARD, 22));
        rx = metric(metrics, "Получено"); tx = metric(metrics, "Отправлено"); latency = metric(metrics, "Задержка"); Ui.add(this, body, metrics, 34);
        LinearLayout card = Ui.column(this); card.setPadding(dp(20), dp(20), dp(20), dp(20)); card.setBackground(Ui.shape(this, Ui.CARD, 22));
        card.addView(Ui.text(this, "ПРОФИЛЬ ПОДКЛЮЧЕНИЯ", 11, Ui.MUTED, true));
        profile = Ui.text(this, "Добавьте профиль", 19, Ui.TEXT, true); Ui.add(this, card, profile, 14);
        endpoint = Ui.text(this, "Личный профиль от вашего сервера", 13, Ui.MUTED, false); Ui.add(this, card, endpoint, 8);
        importer = Ui.button(this, "Импортировать профиль", false); importer.setBackground(new android.graphics.drawable.RippleDrawable(ColorStateList.valueOf(0x24FFFFFF), Ui.shape(this, Color.rgb(38, 55, 58), 14), null));
        importer.setOnClickListener(v -> startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*"), 43)); Ui.add(this, card, importer, 18); Ui.add(this, body, card, 14);
        settings = Ui.button(this, "Настройки соединения", false); settings.setOnClickListener(v -> showSettings()); Ui.add(this, body, settings, 14);
        Ui.add(this, body, centered("Без root. По своему маршруту.", 12, Ui.MUTED, false), 24);
        loadProfile(); render();
    }
    private void showSettings() {
        LinearLayout content = Ui.column(this); content.setPadding(dp(24), dp(8), dp(24), dp(8));
        Switch awake = new Switch(this); awake.setText("Связь при выключенном экране"); awake.setTextSize(15); awake.setTextColor(Ui.TEXT); awake.setPadding(0, dp(12), 0, dp(12));
        awake.setChecked(getSharedPreferences("ui", MODE_PRIVATE).getBoolean("awake", false)); awake.setEnabled(!VpnState.running);
        awake.setOnCheckedChangeListener((v, checked) -> getSharedPreferences("ui", MODE_PRIVATE).edit().putBoolean("awake", checked).apply()); content.addView(awake);
        Ui.add(this, content, Ui.text(this, "Помогает поддерживать фоновое соединение и повышает расход батареи. Меняйте настройку до подключения.", 14, Ui.MUTED, false), 12);
        Ui.add(this, content, Ui.text(this, "При потере связи VPN удерживает трафик до восстановления соединения. Чтобы защитить трафик и после остановки приложения, включите «Блокировать подключения без VPN» в системных настройках Android.", 14, Ui.MUTED, false), 20);
        new android.app.AlertDialog.Builder(this).setTitle("Настройки соединения").setView(content).setPositiveButton("Готово", null).show();
    }
    private static final class PowerButton extends Button {
        private final android.graphics.Paint paint = new android.graphics.Paint(android.graphics.Paint.ANTI_ALIAS_FLAG);
        PowerButton(Activity a) {
            super(a); setText(""); setContentDescription("Подключить"); setMinWidth(0); setMinHeight(0);
            setStateListAnimator(null);
            setBackground(new android.graphics.drawable.RippleDrawable(ColorStateList.valueOf(0x3388AA55), Ui.shape(a, Ui.ACCENT, 100), null));
        }
        @Override protected void onDraw(android.graphics.Canvas canvas) {
            super.onDraw(canvas); float scale = getWidth() / 176f; float x = getWidth() / 2f, y = getHeight() / 2f;
            paint.setColor(Ui.INK); paint.setStyle(android.graphics.Paint.Style.STROKE); paint.setStrokeWidth(5 * scale); paint.setStrokeCap(android.graphics.Paint.Cap.ROUND);
            canvas.drawArc(x - 28 * scale, y - 28 * scale, x + 28 * scale, y + 28 * scale, -48, 276, false, paint);
            canvas.drawLine(x, y - 35 * scale, x, y - 4 * scale, paint);
        }
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
                main.post(() -> { if (isDestroyed()) return; haveProfile = true; profile.setText(name); this.endpoint.setText(endpoint); importer.setText("Заменить профиль"); render(); });
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
        status.setText(VpnState.message);
        detail.setText(!haveProfile && !VpnState.running ? "Добавьте профиль, чтобы начать" : VpnState.detail);
        boolean enabled = haveProfile || VpnState.running;
        connect.setEnabled(enabled); connect.setAlpha(enabled ? 1f : .35f);
        String label = VpnState.running ? "Отключить" : "Подключить";
        connect.setContentDescription(label); action.setText(label);
        importer.setEnabled(!VpnState.running); importer.setAlpha(VpnState.running ? .45f : 1f);
        try {
            JSONObject s = new JSONObject(VpnState.stats);
            rx.setText(VpnState.running && s.has("rx_bytes") ? String.format(java.util.Locale.getDefault(), "%.1f МБ", s.optLong("rx_bytes") / 1000000.0) : "—");
            tx.setText(VpnState.running && s.has("tx_bytes") ? String.format(java.util.Locale.getDefault(), "%.1f МБ", s.optLong("tx_bytes") / 1000000.0) : "—");
            latency.setText(VpnState.running && s.optLong("rtt_us") > 0 ? String.format(java.util.Locale.getDefault(), "%.0f мс", s.optLong("rtt_us") / 1000.0) : "—");
        } catch (Exception ignored) { rx.setText("—"); tx.setText("—"); latency.setText("—"); }
    }
    @Override protected void onResume() { super.onResume(); main.post(refresh); }
    @Override protected void onPause() { main.removeCallbacks(refresh); super.onPause(); }
    @Override protected void onDestroy() { main.removeCallbacksAndMessages(null); files.shutdown(); super.onDestroy(); }
}
