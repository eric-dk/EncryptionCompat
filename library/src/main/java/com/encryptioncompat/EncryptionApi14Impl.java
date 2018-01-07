package com.encryptioncompat;

import android.annotation.TargetApi;
import java.security.GeneralSecurityException;
import java.security.Key;
import javax.crypto.Cipher;

@TargetApi(18)
class EncryptionApi14Impl extends EncryptionBaseImpl {
    private Cipher cipher;
    private Key key;
    private String password;

    private EncryptionApi14Impl() {}
    static EncryptionApi14Impl get() {
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
        static final EncryptionApi14Impl INSTANCE = new EncryptionApi14Impl();
    }
}
