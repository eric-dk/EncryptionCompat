package com.encryptioncompat;

import android.annotation.TargetApi;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import java.security.GeneralSecurityException;
import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

@TargetApi(23)
class EncryptionApi23Impl extends EncryptionBaseImpl {
    private static final String MASTER_KEY = "SYMMETRIC_KEY";

    private Cipher cipher;
    private Key key;

    private EncryptionApi23Impl() {}
    static EncryptionApi23Impl get() {
        return Lazy.INSTANCE;
    }

    @Override
    Cipher getSymmetricCipher() throws GeneralSecurityException {
        if (cipher == null) {
            cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        }
        return cipher;
    }

    @Override
    Key getSymmetricKey() throws GeneralSecurityException {
        if (key == null) {
            KeyGenerator generator = KeyGenerator
                    .getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(MASTER_KEY,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build();

            generator.init(spec);
            key = generator.generateKey();
        }
        return key;
    }

    private static final class Lazy {
        static final EncryptionApi23Impl INSTANCE = new EncryptionApi23Impl();
    }
}
