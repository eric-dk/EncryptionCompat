package com.encryptioncompat;

import android.util.Base64;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

abstract class EncryptionBaseImpl {
    static final String FIELD_SEPARATOR = "]";

    private final Cipher cipher;
    final SecureRandom random;

    EncryptionBaseImpl() {
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        } catch (GeneralSecurityException e) {
            throw new EncryptionException(e);
        }
        random = new SecureRandom();
    }

    synchronized final String encrypt(Key key, byte[] plainText) throws EncryptionException {
        byte[] iv = new byte[cipher.getBlockSize()];
        random.nextBytes(iv);
        String ivString = Base64.encodeToString(iv, Base64.DEFAULT);

        String result;
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] cipherText = cipher.doFinal(plainText);
            result = Base64.encodeToString(cipherText, Base64.DEFAULT);
        } catch (GeneralSecurityException e) {
            throw new EncryptionException(e);
        }
        return ivString + FIELD_SEPARATOR + result;
    }

    synchronized final String decrypt(Key key,
                                      byte[] iv,
                                      byte[] cipherText) throws EncryptionException {
        String result;
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] plainText = cipher.doFinal(cipherText);
            result = new String(plainText);
        } catch (GeneralSecurityException e) {
            throw new EncryptionException(e);
        }
        return result;
    }
}
