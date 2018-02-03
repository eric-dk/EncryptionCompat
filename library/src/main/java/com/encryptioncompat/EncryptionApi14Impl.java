package com.encryptioncompat;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import static android.content.Context.MODE_PRIVATE;
import static android.util.Base64.DEFAULT;

class EncryptionApi14Impl extends EncryptionBaseImpl {
    private static final Object LOCK       = new Object();

    private static final int SALT_SIZE     = KEY_SIZE / 8;
    private static final String MASTER_KEY = EncryptionApi14Impl.class.getSimpleName();
    private static final String PREFS_NAME = EncryptionCompat.class.getSimpleName();

    private static volatile EncryptionApi14Impl singleton;

    private final char[] password;
    private final SecretKeyFactory factory;
    private final SecureRandom random;

    private EncryptionApi14Impl(Context context) {
        password = getPassword(context);
        try {
            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionException(e);
        }
        random = new SecureRandom();
    }

    private char[] getPassword(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        String result = prefs.getString(MASTER_KEY, null);

        if (result == null) {
            byte[] bytes = new byte[128];
            random.nextBytes(bytes);
            result = Base64.encodeToString(bytes, DEFAULT);
            prefs.edit().putString(MASTER_KEY, result).apply();
        }
        return result.toCharArray();
    }

    static EncryptionApi14Impl get(Context context) {
        EncryptionApi14Impl instance = singleton;
        if (instance == null) {
            synchronized (EncryptionApi14Impl.class) {
                instance = singleton;
                if (instance == null) {
                    singleton = instance = new EncryptionApi14Impl(context);
                }
            }
        }
        return instance;
    }

    String encrypt(String data) {
        byte[] salt = new byte[SALT_SIZE];
        random.nextBytes(salt);
        String saltString = Base64.encodeToString(salt, DEFAULT);

        Key key;
        try {
            key = getKey(salt);
        } catch (GeneralSecurityException e) {
            throw new EncryptionException(e);
        }
        String result = encrypt(key, data.getBytes());
        return saltString + FIELD_SEPARATOR + result;
    }

    String decrypt(String data) {
        String[] fields = data.split(FIELD_SEPARATOR);
        if (fields.length != 3) {
            throw new EncryptionException("Invalid format");
        }

        byte[] salt = Base64.decode(fields[0], DEFAULT);
        byte[] iv = Base64.decode(fields[1], DEFAULT);
        byte[] cipherText = Base64.decode(fields[2], DEFAULT);

        Key key;
        try {
            key = getKey(salt);
        } catch (GeneralSecurityException e) {
            throw new EncryptionException(e);
        }
        return decrypt(key, iv, cipherText);
    }

    private Key getKey(byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, 1000, KEY_SIZE);
        byte[] encoded;
        synchronized (LOCK) {
            encoded = factory.generateSecret(spec).getEncoded();
        }
        return new SecretKeySpec(encoded, KEY_ALGORITHM);
    }
}
