package io.github.bug0000.pingtun;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.platform.app.InstrumentationRegistry;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.Test;
import org.junit.runner.RunWith;
import static org.junit.Assert.*;

@RunWith(AndroidJUnit4.class)
public final class ClientTest {
    private String profile() throws Exception {
        byte[] bytes = new byte[32]; bytes[0] = 1;
        String key = android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP);
        JSONObject c = new JSONObject().put("role", "client").put("interface", "pingtun0").put("listen", "0.0.0.0")
            .put("server_ip", "192.0.2.1").put("private_key", key).put("peer_public_key", key).put("transport_key", key)
            .put("allowed_ips", new JSONArray().put("0.0.0.0/0")).put("mtu", 1280).put("wire_mtu", 1440)
            .put("lanes", 2).put("window", 4).put("hold_ms", 500).put("socket_mode", "ping")
            .put("adaptive", new JSONObject().put("id_mode", "stable"));
        return new JSONObject().put("version", 1).put("name", "Instrumented test").put("address", "10.203.0.2/30")
            .put("dns", new JSONArray().put("1.1.1.1")).put("config", c).toString();
    }
    private boolean contains(android.view.View view, String text) {
        if (view instanceof android.widget.TextView && ((android.widget.TextView)view).getText().toString().contains(text)) return true;
        if (view instanceof android.view.ViewGroup) {
            android.view.ViewGroup group = (android.view.ViewGroup)view;
            for (int i = 0; i < group.getChildCount(); i++) if (contains(group.getChildAt(i), text)) return true;
        }
        return false;
    }
    @Test public void aboutShowsVersionDescriptionAndContact() throws Exception {
        android.app.Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
        Context context = instrumentation.getTargetContext();
        android.app.Activity activity = instrumentation.startActivitySync(new android.content.Intent(context, AboutActivity.class).addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK));
        instrumentation.waitForIdleSync();
        android.os.SystemClock.sleep(800);
        instrumentation.runOnMainSync(() -> {
            android.view.View root = activity.getWindow().getDecorView();
            assertTrue(contains(root, "О приложении")); assertTrue(contains(root, "bug@pizd.ec"));
            assertTrue(contains(root, BuildConfig.VERSION_NAME)); assertTrue(contains(root, "ICMP"));
            assertFalse(contains(root, "Pixel")); assertFalse(contains(root, "эксперимент"));
        });
        android.graphics.Bitmap screenshot = instrumentation.getUiAutomation().takeScreenshot();
        assertNotNull(screenshot);
        try (java.io.FileOutputStream out = context.openFileOutput("about-preview.png", Context.MODE_PRIVATE)) {
            screenshot.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, out);
        } finally { screenshot.recycle(); instrumentation.runOnMainSync(activity::finish); }
    }
    @Test public void mainHasCleanConnectionActionsAndLauncherIcon() throws Exception {
        android.app.Instrumentation instrumentation = InstrumentationRegistry.getInstrumentation();
        Context context = instrumentation.getTargetContext();
        assertNotNull(context.getPackageManager().getApplicationIcon(context.getPackageName()));
        android.app.Activity activity = instrumentation.startActivitySync(new android.content.Intent(context, MainActivity.class).addFlags(android.content.Intent.FLAG_ACTIVITY_NEW_TASK));
        instrumentation.waitForIdleSync();
        android.os.SystemClock.sleep(800);
        instrumentation.runOnMainSync(() -> {
            android.view.View root = activity.getWindow().getDecorView();
            assertTrue(contains(root, "О приложении")); assertTrue(contains(root, "Импортировать профиль"));
            assertTrue(contains(root, "Подключить")); assertFalse(contains(root, "Pixel"));
            assertFalse(contains(root, "эксперимент"));
        });
        android.graphics.Bitmap screenshot = instrumentation.getUiAutomation().takeScreenshot();
        assertNotNull(screenshot);
        try (java.io.FileOutputStream out = context.openFileOutput("main-preview.png", Context.MODE_PRIVATE)) {
            screenshot.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, out);
        } finally { screenshot.recycle(); instrumentation.runOnMainSync(activity::finish); }
    }
    @Test public void nativeProfileValidationExposesNoKeys() throws Exception {
        JSONObject info = new JSONObject(NativeEngine.inspect(profile()));
        assertEquals("192.0.2.1", info.getString("server_ip"));
        assertFalse(info.has("config")); assertFalse(info.has("private_key"));
        assertTrue(new JSONObject(NativeEngine.inspect("{\"private_key\":\"secret\"}")).has("error"));
    }
    @Test public void rootlessIcmpSocketCanBeOpened() {
        assertTrue("test must execute as an app UID", android.os.Process.myUid() >= 10000);
        assertNull("AOSP app should be allowed a datagram ICMP socket", NativeEngine.probeSocket());
    }
    @Test public void profileIsEncryptedAndAuthenticationFailureIsRejected() throws Exception {
        Context context = InstrumentationRegistry.getInstrumentation().getTargetContext();
        ProfileStore store = new ProfileStore(context); String plain = profile();
        store.save(plain); assertEquals(plain, store.load());
        File file = new File(context.getNoBackupFilesDir(), "profile.enc");
        byte[] encrypted = Files.readAllBytes(file.toPath());
        assertFalse(new String(encrypted, StandardCharsets.UTF_8).contains("private_key"));
        encrypted[encrypted.length - 1] ^= 1; Files.write(file.toPath(), encrypted);
        boolean rejected = false;
        try { store.load(); } catch (Exception expected) { rejected = true; }
        assertTrue("modified ciphertext must fail authentication", rejected);
        file.delete();
        assertEquals(0, context.getApplicationInfo().flags & ApplicationInfo.FLAG_ALLOW_BACKUP);
    }
}
