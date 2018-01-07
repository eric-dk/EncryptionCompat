package com.encryptioncompat;

import android.annotation.TargetApi;
import java.security.GeneralSecurityException;
import java.security.Key;
import javax.crypto.Cipher;

@TargetApi(18)
class EncryptionApi18Impl extends EncryptionBaseImpl {
    private static final String MASTER_KEY = "ASYMMETRIC_KEY";

    private Cipher cipher;
    private Key key;

    private EncryptionApi18Impl() {}
    static EncryptionApi18Impl get() {
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

        }
        return key;
    }

    private static final class Lazy {
        static final EncryptionApi18Impl INSTANCE = new EncryptionApi18Impl();
    }
}
