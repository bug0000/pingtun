package io.github.bug0000.pingtun;

import android.app.Activity;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.RippleDrawable;
import android.os.Build;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

final class Ui {
    static final int BG = Color.rgb(13, 22, 25), CARD = Color.rgb(24, 36, 40);
    static final int TEXT = Color.rgb(240, 245, 240), MUTED = Color.rgb(163, 183, 179);
    static final int ACCENT = Color.rgb(119, 215, 255), INK = Color.rgb(14, 37, 49);
    private Ui() { }
    static int dp(Activity a, int n) { return Math.round(a.getResources().getDisplayMetrics().density * n); }
    static GradientDrawable shape(Activity a, int color, int radius) {
        GradientDrawable d = new GradientDrawable(); d.setColor(color); d.setCornerRadius(dp(a, radius)); return d;
    }
    static TextView text(Activity a, String value, int size, int color, boolean bold) {
        TextView t = new TextView(a); t.setText(value); t.setTextSize(size); t.setTextColor(color);
        t.setFontFeatureSettings("kern");
        t.setTypeface(Typeface.create(bold ? "sans-serif-medium" : "sans-serif", Typeface.NORMAL));
        t.setIncludeFontPadding(false); t.setLineSpacing(dp(a, 3), 1f); return t;
    }
    static Button button(Activity a, String label, boolean primary) {
        Button b = new Button(a); b.setText(label); b.setAllCaps(false); b.setTextSize(15);
        b.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        b.setTextColor(primary ? INK : TEXT); b.setMinHeight(dp(a, 50));
        b.setPadding(dp(a, 18), dp(a, 10), dp(a, 18), dp(a, 10));
        b.setBackground(new RippleDrawable(ColorStateList.valueOf(0x24FFFFFF), shape(a, primary ? ACCENT : CARD, 16), null));
        b.setStateListAnimator(null); return b;
    }
    static LinearLayout column(Activity a) {
        LinearLayout l = new LinearLayout(a); l.setOrientation(LinearLayout.VERTICAL); return l;
    }
    static void add(Activity a, LinearLayout parent, View view, int top) {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2); lp.topMargin = dp(a, top); parent.addView(view, lp);
    }
    static void insets(Activity a, View body) {
        body.setOnApplyWindowInsetsListener((view, insets) -> {
            if (Build.VERSION.SDK_INT >= 30) {
                android.graphics.Insets bars = insets.getInsets(android.view.WindowInsets.Type.systemBars());
                view.setPadding(dp(a, 24) + bars.left, dp(a, 20) + bars.top, dp(a, 24) + bars.right, dp(a, 28) + bars.bottom);
            } else view.setPadding(dp(a, 24) + insets.getSystemWindowInsetLeft(), dp(a, 20) + insets.getSystemWindowInsetTop(), dp(a, 24) + insets.getSystemWindowInsetRight(), dp(a, 28) + insets.getSystemWindowInsetBottom());
            return insets;
        });
        body.requestApplyInsets();
    }
}
