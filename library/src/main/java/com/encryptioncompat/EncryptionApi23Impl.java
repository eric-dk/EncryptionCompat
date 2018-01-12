package com.encryptioncompat;

import android.annotation.TargetApi;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import javax.crypto.KeyGenerator;

@TargetApi(23)
final class EncryptionApi23Impl extends EncryptionBaseImpl {
    private static final String KEY_PROVIDER = "AndroidKeyStore";
    private static final String MASTER_KEY   = EncryptionApi23Impl.class.getSimpleName();

    private final Key key;

    private EncryptionApi23Impl() {
        try {
            KeyStore keyStore = KeyStore.getInstance(KEY_PROVIDER);
            keyStore.load(null);

            if (keyStore.containsAlias(MASTER_KEY)) {
                key = keyStore.getKey(MASTER_KEY, null);
            } else {
                key = createKey();
            }
        } catch (GeneralSecurityException | IOException e) {
            throw new EncryptionException(e);
        }
    }

    private Key createKey() throws GeneralSecurityException, IOException {
        KeyGenerator generator = KeyGenerator.getInstance("AES", KEY_PROVIDER);
        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(MASTER_KEY,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .build();

        generator.init(spec);
        return generator.generateKey();
    }

    static EncryptionApi23Impl get() {
        return Holder.SINGLETON;
    }

    synchronized String encrypt(String data) throws EncryptionException {
        return encrypt(key, data.getBytes());
    }

    synchronized String decrypt(String data) throws EncryptionException {
        String[] fields = data.split(FIELD_SEPARATOR);
        if (fields.length != 2) {
            throw new EncryptionException("Invalid format");
        }

        byte[] iv = Base64.decode(fields[0], Base64.DEFAULT);
        byte[] cipherText = Base64.decode(fields[1], Base64.DEFAULT);
        return decrypt(key, iv, cipherText);
    }

    private static final class Holder {
        static final EncryptionApi23Impl SINGLETON = new EncryptionApi23Impl();
    }
}
