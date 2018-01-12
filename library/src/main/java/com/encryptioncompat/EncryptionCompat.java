package com.encryptioncompat;

import android.content.Context;
import android.os.Build;
import android.support.annotation.NonNull;

public final class EncryptionCompat {
    private static final String AES_KEYSTORE = "0";
    private static final String RSA_KEYSTORE = "1";
    private static final String SHARED_PREFS = "2";

    @NonNull
    public static String encrypt(@NonNull String data,
                                 @NonNull Context context) throws EncryptionException {
        if (data.isEmpty()) {
            return data;
        }
        switch (Build.VERSION.SDK_INT) {
            case 23:
                return AES_KEYSTORE + EncryptionApi23Impl.get().encrypt(data);
            case 18:
                return RSA_KEYSTORE + EncryptionApi18Impl.get(context).encrypt(data);
            default:
                return SHARED_PREFS + EncryptionApi14Impl.get(context).encrypt(data);
        }
    }

    @NonNull
    public static String decrypt(@NonNull String data,
                                 @NonNull Context context) throws EncryptionException {
        if (data.isEmpty()) {
            return data;
        }
        String mode = data.substring(0, 1);
        String encoded = data.substring(1);
        switch (mode) {
            case AES_KEYSTORE:
                requireApi(23);
                return EncryptionApi23Impl.get().decrypt(encoded);
            case RSA_KEYSTORE:
                requireApi(18);
                return EncryptionApi18Impl.get(context).decrypt(encoded);
            case SHARED_PREFS:
                return EncryptionApi14Impl.get(context).decrypt(encoded);
            default:
                throw new EncryptionException("Unknown encryption");
        }
    }

    private static void requireApi(int level) throws EncryptionException {
        if (Build.VERSION.SDK_INT < level) {
            throw new EncryptionException("Requires API " + level);
        }
    }
}
