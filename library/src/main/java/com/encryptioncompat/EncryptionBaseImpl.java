package com.encryptioncompat;

import android.util.Base64;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;

abstract class EncryptionBaseImpl {
    private static final String IV_SEPARATOR = "]";

    final SecureRandom random = new SecureRandom();

    abstract Cipher getSymmetricCipher() throws GeneralSecurityException;
    abstract Key getSymmetricKey() throws GeneralSecurityException;

    synchronized String encrypt(String value) throws GeneralSecurityException {
        Cipher cipher = getSymmetricCipher();
        Key key = getSymmetricKey();

        byte[] iv = new byte[cipher.getBlockSize()];
        random.nextBytes(iv);
        String ivString = Base64.encodeToString(iv, Base64.DEFAULT);

        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] encoded = cipher.doFinal(value.getBytes());
        String encodedString = Base64.encodeToString(encoded, Base64.DEFAULT);

        return ivString + IV_SEPARATOR + encodedString;
    }

    synchronized String decrypt(String value) throws GeneralSecurityException {
        String[] fields = value.split(IV_SEPARATOR);
        if (fields.length != 2) {
            throw new IllegalStateException("IV not found");
        }

        Cipher cipher = getSymmetricCipher();
        Key key = getSymmetricKey();

        String ivString = fields[0];
        String encodedString = fields[1];

        byte[] iv = Base64.decode(ivString, Base64.DEFAULT);
        byte[] encoded = Base64.decode(encodedString, Base64.DEFAULT);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        return new String(cipher.doFinal(encoded));
    }
}
