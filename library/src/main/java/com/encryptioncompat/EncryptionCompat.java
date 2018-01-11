package com.encryptioncompat;

import android.os.Build;
import android.support.annotation.NonNull;
import android.support.annotation.RequiresApi;

public final class EncryptionCompat {
    private static final String AES_KEYSTORE  = "0";
    private static final String RSA_KEYSTORE  = "1";
    private static final String USER_PASSWORD = "2";

    @NonNull
    @RequiresApi(18)
    public static String encrypt(@NonNull String data) throws EncryptionException {
        if (data.isEmpty()) {
            return data;
        }
        return encrypt(Build.VERSION.SDK_INT, data, null);
    }

    @NonNull
    public static String encrypt(@NonNull String data,
                                 @NonNull String password) throws EncryptionException {
        if (data.isEmpty()) {
            return data;
        }
        return encrypt(Build.VERSION.SDK_INT, data, password);
    }

    private static String encrypt(int api,
                                  String data,
                                  String password) throws EncryptionException {
        switch (api) {
            case 23:
                return AES_KEYSTORE + EncryptionApi23Impl.get().encrypt(data);
            case 18:
                return RSA_KEYSTORE + EncryptionApi18Impl.get().encrypt(data);
            default:
                checkNotNull(password);
                return USER_PASSWORD + EncryptionApi14Impl.get().encrypt(data, password);
        }
    }

    @NonNull
    @RequiresApi(18)
    public static String decrypt(@NonNull String data)
            throws EncryptionException {
        if (data.isEmpty()) {
            return data;
        }

        String mode = data.substring(0, 1);
        String encoded = data.substring(1);
        return decrypt(mode, encoded, null);
    }

    @NonNull
    public static String decrypt(@NonNull String data,
                                 @NonNull String password) throws EncryptionException {
        if (data.isEmpty()) {
            return data;
        }

        String mode = data.substring(0, 1);
        String encoded = data.substring(1);
        return decrypt(mode, encoded, password);
    }

    private static String decrypt(String mode,
                                  String data,
                                  String password) throws EncryptionException {
        switch (mode) {
            case AES_KEYSTORE:
                checkAtLeast(23);
                return EncryptionApi23Impl.get().decrypt(data);
            case RSA_KEYSTORE:
                checkAtLeast(18);
                return EncryptionApi18Impl.get().decrypt(data);
            case USER_PASSWORD:
                checkNotNull(password);
                return EncryptionApi14Impl.get().decrypt(data, password);
            default:
                throw new EncryptionException("Unknown encryption");
        }
    }

    private static void checkAtLeast(int version) throws EncryptionException {
        if (Build.VERSION.SDK_INT < version) {
            throw new EncryptionException("Requires API " + version);
        }
    }

    private static void checkNotNull(String password) throws EncryptionException {
        if (password == null) {
            throw new EncryptionException("Requires password");
        }
    }
}
