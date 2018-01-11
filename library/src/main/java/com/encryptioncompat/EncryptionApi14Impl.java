package com.encryptioncompat;

import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

final class EncryptionApi14Impl extends EncryptionSecretImpl {
    private static final int ITERATION_COUNT = 1000;

    private final SecretKeyFactory factory;

    private EncryptionApi14Impl() {
        try {
            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionException(e);
        }
    }

    static EncryptionApi14Impl get() {
        return Lazy.INSTANCE;
    }

    @Override
    Key getKey(String password, byte[] salt, int keyLength) throws GeneralSecurityException {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATION_COUNT, keyLength);
        byte[] encoded = factory.generateSecret(spec).getEncoded();
        return new SecretKeySpec(encoded, "AES");
    }

    private static final class Lazy {
        static final EncryptionApi14Impl INSTANCE = new EncryptionApi14Impl();
    }
}
