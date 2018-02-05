/*
 * Copyright © 2018 Eric Nguyen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.encryptioncompat;

import android.content.Context;
import android.support.annotation.AnyThread;
import android.support.annotation.CheckResult;
import android.support.annotation.NonNull;
import android.support.annotation.VisibleForTesting;
import static android.os.Build.VERSION.SDK_INT;
import static android.os.Build.VERSION_CODES.JELLY_BEAN_MR2;
import static android.os.Build.VERSION_CODES.M;

public final class EncryptionCompat {
    @VisibleForTesting static final String AES_KEYSTORE = "0";
    @VisibleForTesting static final String RSA_KEYSTORE = "1";
    @VisibleForTesting static final String SHARED_PREFS = "2";

    /**
     * Encrypts {@code data} with AES-256, CBC, PKCS7-padded key. Key management and security
     * differs depending on the Android version.
     *
     * @param  data                String to encrypt
     * @param  context             For accessing shared preferences
     * @throws EncryptionException Can be rethrown exception
     */
    @AnyThread
    @CheckResult
    @NonNull
    public static String encrypt(@NonNull String data,
                                 @NonNull Context context) throws EncryptionException {
        if (data.isEmpty()) {
            return data;
        } else if (SDK_INT >= M) {
            return AES_KEYSTORE + EncryptionApi23Impl.get().encrypt(data);
        } else if (SDK_INT >= JELLY_BEAN_MR2) {
            return RSA_KEYSTORE + EncryptionApi18Impl.get(context).encrypt(data);
        } else {
            return SHARED_PREFS + EncryptionApi14Impl.get(context).encrypt(data);
        }
    }

    /**
     * Decrypts {@code data} according to encryption mode. Will throw {@code EncryptionException}
     * if encryption mode not supported.
     *
     * @param  data                String to decrypt
     * @param  context             For accessing shared preferences
     * @return                     May be invalid if stored key missing
     * @throws EncryptionException Can also be rethrown exception
     */
    @AnyThread
    @CheckResult
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
                if (SDK_INT >= M) {
                    return EncryptionApi23Impl.get().decrypt(encoded);
                }
                throw new EncryptionException("Requires Marshmallow");
            case RSA_KEYSTORE:
                if (SDK_INT >= JELLY_BEAN_MR2) {
                    return EncryptionApi18Impl.get(context).decrypt(encoded);
                }
                throw new EncryptionException("Requires Jelly Bean MR2");
            case SHARED_PREFS:
                return EncryptionApi14Impl.get(context).decrypt(encoded);
            default:
                throw new EncryptionException("Unknown encryption");
        }
    }
}
