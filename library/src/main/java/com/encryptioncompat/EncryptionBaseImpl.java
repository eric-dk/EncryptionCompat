package com.encryptioncompat;

import android.util.Base64;
import java.security.GeneralSecurityException;
import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import static android.util.Base64.DEFAULT;
import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;

abstract class EncryptionBaseImpl {
    private static final Object LOCK    = new Object();

    static final int KEY_SIZE           = 256;
    static final String KEY_ALGORITHM   = "AES";
    static final String FIELD_SEPARATOR = "]";

    private final Cipher cipher;

    EncryptionBaseImpl() {
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        } catch (GeneralSecurityException e) {
            throw new EncryptionException(e);
        }
    }

    String encrypt(Key key, byte[] plainText) {
        byte[] iv;
        byte[] cipherText;
        try {
            synchronized (LOCK) {
                cipher.init(ENCRYPT_MODE, key);
                iv = cipher.getIV();
                cipherText = cipher.doFinal(plainText);
            }
        } catch (GeneralSecurityException e) {
            throw new EncryptionException(e);
        }

        String ivString = Base64.encodeToString(iv, DEFAULT);
        String result = Base64.encodeToString(cipherText, DEFAULT);
        return ivString + FIELD_SEPARATOR + result;
    }

    String decrypt(Key key, byte[] iv, byte[] cipherText) {
        byte[] plainText;
        try {
            synchronized (LOCK) {
                cipher.init(DECRYPT_MODE, key, new IvParameterSpec(iv));
                plainText = cipher.doFinal(cipherText);
            }
        } catch (GeneralSecurityException e) {
            throw new EncryptionException(e);
        }
        return new String(plainText);
    }
}
