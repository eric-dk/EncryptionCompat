package com.encryptioncompat;

import android.annotation.TargetApi;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import javax.crypto.KeyGenerator;

@TargetApi(23)
final class EncryptionApi23Impl extends EncryptionKeyStoreImpl {
    private static final String KEY_PROVIDER = "AndroidKeyStore";
    private static final String MASTER_KEY   = "SYMMETRIC_KEY";

    private Key key;

    static EncryptionApi23Impl get() {
        return Lazy.INSTANCE;
    }

    @Override
    Key getKey() throws EncryptionException {
        if (key == null) {
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
        return key;
    }

    private Key createKey() throws GeneralSecurityException {
        KeyGenerator generator = KeyGenerator
                .getInstance(KeyProperties.KEY_ALGORITHM_AES, KEY_PROVIDER);
        KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(MASTER_KEY,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                .build();

        generator.init(spec);
        return generator.generateKey();
    }

    private static final class Lazy {
        static final EncryptionApi23Impl INSTANCE = new EncryptionApi23Impl();
    }
}
