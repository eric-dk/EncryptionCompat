package com.encryptioncompat;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import static android.content.Context.MODE_PRIVATE;

final class EncryptionApi14Impl extends EncryptionBaseImpl {
    private static final int ITERATION_COUNT = 1000;
    private static final int KEY_LENGTH      = 256;
    private static final int SALT_LENGTH     = KEY_LENGTH / 8;

    private static final String MASTER_KEY   = EncryptionApi14Impl.class.getSimpleName();
    private static final String PREFS_NAME   = EncryptionCompat.class.getSimpleName();

    private static volatile EncryptionApi14Impl singleton;

    private final char[] password;
    private final SecretKeyFactory factory;

    private EncryptionApi14Impl(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, MODE_PRIVATE);
        if (prefs.contains(MASTER_KEY)) {
            password = prefs.getString(MASTER_KEY, createPassword(prefs)).toCharArray();
        } else {
            password = createPassword(prefs).toCharArray();
        }
        try {
            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionException(e);
        }
    }

    private String createPassword(SharedPreferences prefs) {
        byte[] bytes = new byte[128];
        random.nextBytes(bytes);
        String result = Base64.encodeToString(bytes, Base64.DEFAULT);

        prefs.edit().putString(MASTER_KEY, result).apply();
        return result;
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

    synchronized String encrypt(String data) throws EncryptionException {
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        String saltString = Base64.encodeToString(salt, Base64.DEFAULT);

        Key key;
        try {
            key = getKey(salt);
        } catch (GeneralSecurityException e) {
            throw new EncryptionException(e);
        }
        String result = encrypt(key, data.getBytes());
        return saltString + FIELD_SEPARATOR + result;
    }

    synchronized String decrypt(String data) throws EncryptionException {
        String[] fields = data.split(FIELD_SEPARATOR);
        if (fields.length != 3) {
            throw new EncryptionException("Invalid format");
        }

        byte[] salt = Base64.decode(fields[0], Base64.DEFAULT);
        byte[] iv = Base64.decode(fields[1], Base64.DEFAULT);
        byte[] cipherText = Base64.decode(fields[2], Base64.DEFAULT);

        Key key;
        try {
            key = getKey(salt);
        } catch (GeneralSecurityException e) {
            throw new EncryptionException(e);
        }
        return decrypt(key, iv, cipherText);
    }

    private Key getKey(byte[] salt) throws GeneralSecurityException {
        KeySpec spec = new PBEKeySpec(password, salt, ITERATION_COUNT, KEY_LENGTH);
        byte[] encoded = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(encoded, "AES");
    }
}
