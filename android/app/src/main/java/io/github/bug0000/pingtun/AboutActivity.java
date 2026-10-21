package io.github.bug0000.pingtun;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.widget.Button;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

public final class AboutActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        ScrollView scroll = new ScrollView(this); scroll.setBackgroundColor(Ui.BG); scroll.setFillViewport(true);
        LinearLayout body = Ui.column(this); scroll.addView(body); setContentView(scroll); Ui.insets(this, body);
        Button back = Ui.button(this, "← Назад", false); back.setOnClickListener(v -> finish()); Ui.add(this, body, back, 0);
        ImageView icon = new ImageView(this); icon.setImageResource(R.drawable.ic_launcher); icon.setImportantForAccessibility(android.view.View.IMPORTANT_FOR_ACCESSIBILITY_NO);
        LinearLayout.LayoutParams iconParams = new LinearLayout.LayoutParams(Ui.dp(this, 88), Ui.dp(this, 88)); iconParams.topMargin = Ui.dp(this, 36); body.addView(icon, iconParams);
        Ui.add(this, body, Ui.text(this, "О приложении", 30, Ui.TEXT, true), 24);
        Ui.add(this, body, Ui.text(this, "pingtun  /  " + BuildConfig.VERSION_NAME, 15, Ui.ACCENT, true), 12);
        Ui.add(this, body, Ui.text(this, "Не самый прямой путь.\nЗато свой.", 25, Ui.TEXT, true), 32);
        Ui.add(this, body, Ui.text(this, "pingtun — VPN, который передаёт зашифрованный трафик внутри ICMP-пакетов. Тех самых, которыми обычно проверяют, отвечает ли сервер на ping.", 16, Ui.MUTED, false), 18);
        Ui.add(this, body, Ui.text(this, "WireGuard отвечает за ключи и шифрование, а собственный транспорт — за этот небольшой сетевой трюк. Приложение работает без root и Google Play Services.", 16, Ui.MUTED, false), 16);
        Ui.add(this, body, Ui.text(this, "Через туннель передаётся IPv4. IPv6 блокируется, чтобы не обходить VPN. Доступность соединения зависит от того, пропускает ли сеть ICMP.", 15, Ui.MUTED, false), 16);
        Ui.add(this, body, Ui.text(this, "ОБРАТНАЯ СВЯЗЬ", 12, Ui.ACCENT, true), 32);
        Button contact = Ui.button(this, "bug@pizd.ec", false); contact.setContentDescription("Написать на bug@pizd.ec");
        contact.setOnClickListener(v -> open(new Intent(Intent.ACTION_SENDTO, Uri.parse("mailto:bug@pizd.ec")))); Ui.add(this, body, contact, 12);
        Button source = Ui.button(this, "Исходный код  ↗", false);
        source.setOnClickListener(v -> open(new Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/bug0000/pingtun")))); Ui.add(this, body, source, 10);
        TextView footer = Ui.text(this, "Открытый исходный код · MIT License", 13, Ui.MUTED, false); Ui.add(this, body, footer, 28);
    }
    private void open(Intent intent) {
        try { startActivity(intent); }
        catch (ActivityNotFoundException ignored) {
            new android.app.AlertDialog.Builder(this).setTitle("Ссылка")
                .setMessage(intent.getDataString()).setPositiveButton("Скопировать", (dialog, which) -> {
                    android.content.ClipboardManager clipboard = getSystemService(android.content.ClipboardManager.class);
                    clipboard.setPrimaryClip(android.content.ClipData.newPlainText("pingtun", intent.getDataString()));
                }).setNegativeButton("Закрыть", null).show();
        }
    }
}
