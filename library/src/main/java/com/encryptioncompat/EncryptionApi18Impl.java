package com.encryptioncompat;

import android.annotation.TargetApi;
import java.security.Key;

@TargetApi(18)
final class EncryptionApi18Impl extends EncryptionKeyStoreImpl {
    private static final String KEY_PROVIDER = "AndroidKeyStore";
    private static final String MASTER_KEY   = "ASYMMETRIC_KEY";

    private Key key;

    static EncryptionApi18Impl get() {
        return Lazy.INSTANCE;
    }

    @Override
    Key getKey() throws EncryptionException {
        if (key == null) {

        }
        return key;
    }

    private static final class Lazy {
        static final EncryptionApi18Impl INSTANCE = new EncryptionApi18Impl();
    }
}
