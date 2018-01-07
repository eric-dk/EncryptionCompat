package com.encryptioncompat;

import android.os.Build;
import android.support.annotation.NonNull;
import android.support.annotation.RequiresApi;
import java.security.GeneralSecurityException;

public final class EncryptionCompat {
    private static final String KEYSTORE_AES = "0";
    private static final String KEYSTORE_RSA = "1";
    private static final String USR_PASSWORD = "2";

    @NonNull
    @RequiresApi(18)
    public static String encrypt(@NonNull String value)
            throws GeneralSecurityException {
        if (value.isEmpty()) {
            return value;
        }
        return encrypt(Build.VERSION.SDK_INT, value, null);
    }

    @NonNull
    public static String encrypt(@NonNull String value, @NonNull String password)
            throws GeneralSecurityException {
        if (value.isEmpty()) {
            return value;
        }
        return encrypt(Build.VERSION.SDK_INT, value, password);
    }

    private static String encrypt(int api, String value, String password)
            throws GeneralSecurityException {
        switch (api) {
            case 23:
                return KEYSTORE_AES + EncryptionApi23Impl.get().encrypt(value);
            case 18:
                return KEYSTORE_RSA + EncryptionApi18Impl.get().encrypt(value);
            default:
                checkNotNull(password);
                return USR_PASSWORD + "";
        }
    }

    @NonNull
    @RequiresApi(18)
    public static String decrypt(@NonNull String value)
            throws GeneralSecurityException {
        if (value.isEmpty()) {
            return value;
        }

        String mode = value.substring(0, 1);
        String encoded = value.substring(1);
        return decrypt(mode, encoded, null);
    }

    @NonNull
    public static String decrypt(@NonNull String value, @NonNull String password)
            throws GeneralSecurityException {
        if (value.isEmpty()) {
            return value;
        }

        String mode = value.substring(0, 1);
        String encoded = value.substring(1);
        return decrypt(mode, encoded, password);
    }

    private static String decrypt(String mode, String encoded, String password)
            throws GeneralSecurityException {
        switch (mode) {
            case KEYSTORE_AES:
                checkAtLeast(23);
                return EncryptionApi23Impl.get().decrypt(encoded);
            case KEYSTORE_RSA:
                checkAtLeast(18);
                return EncryptionApi18Impl.get().decrypt(encoded);
            case USR_PASSWORD:
                checkNotNull(password);
                return "";
            default:
                throw new IllegalStateException("Unknown encryption");
        }
    }

    private static void checkAtLeast(int version) {
        if (Build.VERSION.SDK_INT < version) {
            throw new UnsupportedOperationException("Requires API " + version);
        }
    }

    private static void checkNotNull(String password) {
        if (password == null) {
            throw new IllegalArgumentException("Requires password");
        }
    }
}
