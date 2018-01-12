package com.encryptioncompat;

import android.annotation.TargetApi;
import android.content.Context;
import android.util.Base64;
import java.security.Key;

@TargetApi(18)
final class EncryptionApi18Impl extends EncryptionBaseImpl {
    private static final String KEY_PROVIDER = "AndroidKeyStore";
    private static final String MASTER_KEY   = EncryptionApi18Impl.class.getSimpleName();

    private static volatile EncryptionApi18Impl singleton;

    private final Key key;

    private EncryptionApi18Impl(Context context) {
        key = null;
    }

    static EncryptionApi18Impl get(Context context) {
        EncryptionApi18Impl instance = singleton;
        if (instance == null) {
            synchronized (EncryptionApi14Impl.class) {
                instance = singleton;
                if (instance == null) {
                    singleton = instance = new EncryptionApi18Impl(context);
                }
            }
        }
        return instance;
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
}
