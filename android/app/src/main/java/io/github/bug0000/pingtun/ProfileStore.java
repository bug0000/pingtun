package io.github.bug0000.pingtun;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.system.Os;
import android.util.AtomicFile;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import org.json.JSONObject;

/** No plaintext profiles, keys or endpoint secrets in preferences, backups or logs. */
final class ProfileStore {
    private static final String ALIAS = "pingtun-profile-v1";
    private final AtomicFile file;
    ProfileStore(Context context) { file = new AtomicFile(new File(context.getNoBackupFilesDir(), "profile.enc")); }
    boolean exists() { return file.getBaseFile().exists(); }
    static byte[] readBounded(InputStream in, int limit) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        for (int n; (n = in.read(buffer)) != -1;) {
            if (out.size() + n > limit) throw new IOException("Profile exceeds 64 KiB");
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
    }
    private static SecretKey key() throws Exception {
        KeyStore store = KeyStore.getInstance("AndroidKeyStore"); store.load(null);
        if (!store.containsAlias(ALIAS)) {
            KeyGenerator gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            gen.init(new KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256).build());
            return gen.generateKey();
        }
        return (SecretKey) store.getKey(ALIAS, null);
    }
    synchronized void save(String profile) throws Exception {
        JSONObject info = new JSONObject(NativeEngine.inspect(profile));
        if (info.has("error")) throw new IOException(info.getString("error"));
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding"); cipher.init(Cipher.ENCRYPT_MODE, key());
        byte[] plain = profile.getBytes(StandardCharsets.UTF_8);
        byte[] encrypted;
        try { encrypted = cipher.doFinal(plain); } finally { Arrays.fill(plain, (byte)0); }
        byte[] iv = cipher.getIV();
        if (iv.length != 12) throw new IOException("Unsupported encryption IV");
        FileOutputStream output = null;
        try {
            output = file.startWrite(); output.write(1); output.write(iv); output.write(encrypted);
            Os.fchmod(output.getFD(), 0600);
            file.finishWrite(output);
        } catch (Exception e) { if (output != null) file.failWrite(output); throw e; }
    }
    synchronized String load() throws Exception {
        byte[] stored;
        try (InputStream in = file.openRead()) { stored = readBounded(in, 65600); }
        if (stored.length < 29 || stored[0] != 1) throw new IOException("Invalid encrypted profile");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(128, Arrays.copyOfRange(stored, 1, 13)));
        byte[] plain = cipher.doFinal(stored, 13, stored.length - 13);
        try { return new String(plain, StandardCharsets.UTF_8); } finally { Arrays.fill(plain, (byte)0); }
    }
}
