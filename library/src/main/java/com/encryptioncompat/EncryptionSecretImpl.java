package com.encryptioncompat;

import android.util.Base64;
import java.security.GeneralSecurityException;
import java.security.Key;

abstract class EncryptionSecretImpl extends EncryptionBaseImpl {
    private static final int KEY_LENGTH  = 256;
    private static final int SALT_LENGTH = KEY_LENGTH / 8;

    abstract Key getKey(String password,
                        byte[] salt,
                        int keyLength) throws GeneralSecurityException;

    synchronized String encrypt(String data, String password) throws EncryptionException {
        byte[] salt = new byte[SALT_LENGTH];
        getRandom().nextBytes(salt);
        String saltString = Base64.encodeToString(salt, Base64.DEFAULT);

        Key key;
        try {
            key = getKey(password, salt, KEY_LENGTH);
        } catch (GeneralSecurityException e) {
            throw new EncryptionException(e);
        }
        String result = encrypt(key, data.getBytes());
        return saltString + FIELD_SEPARATOR + result;
    }

    synchronized String decrypt(String data, String password) throws EncryptionException {
        String[] fields = data.split(FIELD_SEPARATOR);
        if (fields.length != 3) {
            throw new EncryptionException("Invalid format");
        }

        byte[] salt = Base64.decode(fields[0], Base64.DEFAULT);
        byte[] iv = Base64.decode(fields[1], Base64.DEFAULT);
        byte[] cipherText = Base64.decode(fields[2], Base64.DEFAULT);

        Key key;
        try {
            key = getKey(password, salt, KEY_LENGTH);
        } catch (GeneralSecurityException e) {
            throw new EncryptionException(e);
        }
        return decrypt(key, iv, cipherText);
    }
}
