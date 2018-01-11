package com.encryptioncompat;

import android.util.Base64;
import java.security.GeneralSecurityException;
import java.security.Key;

abstract class EncryptionKeyStoreImpl extends EncryptionBaseImpl {
    abstract Key getKey() throws GeneralSecurityException;

    synchronized String encrypt(String data) throws EncryptionException {
        Key key;
        try {
            key = getKey();
        } catch (GeneralSecurityException e) {
            throw new EncryptionException(e);
        }
        return encrypt(key, data.getBytes());
    }

    synchronized String decrypt(String data) throws EncryptionException {
        String[] fields = data.split(FIELD_SEPARATOR);
        if (fields.length != 2) {
            throw new EncryptionException("Invalid format");
        }

        byte[] iv = Base64.decode(fields[0], Base64.DEFAULT);
        byte[] cipherText = Base64.decode(fields[1], Base64.DEFAULT);

        Key key;
        try {
            key = getKey();
        } catch (GeneralSecurityException e) {
            throw new EncryptionException(e);
        }
        return decrypt(key, iv, cipherText);
    }
}
