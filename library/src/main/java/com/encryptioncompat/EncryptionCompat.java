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
import androidx.annotation.CheckResult;
import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.annotation.VisibleForTesting;
import static android.os.Build.VERSION.SDK_INT;
import static android.os.Build.VERSION_CODES.ICE_CREAM_SANDWICH;
import static android.os.Build.VERSION_CODES.JELLY_BEAN_MR2;
import static android.os.Build.VERSION_CODES.M;

public final class EncryptionCompat {
    @VisibleForTesting static final String AES_KEYSTORE = "0";
    @VisibleForTesting static final String RSA_KEYSTORE = "1";
    @VisibleForTesting static final String SHARED_PREFS = "2";

    private final Api14Encryption api14Encryption;
    private final Api18Encryption api18Encryption;
    private final Api23Encryption api23Encryption;

    private EncryptionCompat(Api14Encryption api14Encryption,
                             Api18Encryption api18Encryption,
                             Api23Encryption api23Encryption) {
        this.api14Encryption = api14Encryption;
        this.api18Encryption = api18Encryption;
        this.api23Encryption = api23Encryption;
    }

    /**
     * Encrypts {@code input} with AES-256, CBC, PKCS7-padded key.
     *
     * @param  input                    String to encrypt
     * @throws EncryptionException      Encryption failure
     */
    @CheckResult
    @NonNull
    public String encrypt(@NonNull String input) {
        if (input.isEmpty()) return input;
        if (SDK_INT >= M) return AES_KEYSTORE + api23Encryption.encrypt(input);
        if (SDK_INT >= JELLY_BEAN_MR2) return RSA_KEYSTORE + api18Encryption.encrypt(input);
        return SHARED_PREFS + api14Encryption.encrypt(input);
    }

    /**
     * Decrypts {@code input} according to encoded key mode.
     *
     * @param  input                    String to decrypt
     * @throws EncryptionException      Decryption failure
     */
    @CheckResult
    @NonNull
    public String decrypt(@NonNull String input) {
        if (input.isEmpty()) return input;

        String mode = input.substring(0, 1);
        String encoded = input.substring(1);

        switch (mode) {
            case AES_KEYSTORE:
                if (SDK_INT >= M) return api23Encryption.decrypt(encoded);
                throw new EncryptionException("Requires Marshmallow");
            case RSA_KEYSTORE:
                if (api18Encryption == null) throw new EncryptionException("minSdk too low");
                if (SDK_INT >= JELLY_BEAN_MR2) return api18Encryption.decrypt(encoded);
                throw new EncryptionException("Requires Jelly Bean MR2");
            case SHARED_PREFS:
                if (api14Encryption == null) throw new EncryptionException("minSdk too low");
                return api14Encryption.decrypt(encoded);
            default:
                throw new EncryptionException("Invalid format");
        }
    }

    /**
     * Creates new EncryptionCompat instance with backwards-compatibility down to {@code minSdk}.
     *
     * @param minSdk                    Minimum SDK version; should match manifest
     * @param context                   For generating and retrieving keys
     * @throws EncryptionException      Rethrown key generation or retrieval exception
     */
    @NonNull
    public static EncryptionCompat newInstance(int minSdk, @NonNull Context context) {
        if (minSdk < ICE_CREAM_SANDWICH) {
            throw new EncryptionException("Requires Ice Cream Sandwich");
        } else if (minSdk > SDK_INT) {
            throw new EncryptionException(minSdk + " greater than current version");
        }

        Api14Encryption api14Encryption = null;
        Api18Encryption api18Encryption = null;
        Api23Encryption api23Encryption = null;

        if (minSdk < JELLY_BEAN_MR2) api14Encryption = new Api14Encryption(context);
        if (minSdk < M && SDK_INT >= JELLY_BEAN_MR2) api18Encryption = new Api18Encryption(context);
        if (SDK_INT >= M) api23Encryption = new Api23Encryption();

        return new EncryptionCompat(api14Encryption, api18Encryption, api23Encryption);
    }

    /**
     * Creates new EncryptionCompat instance without backwards-compatibility below Marshmallow.
     *
     * @throws EncryptionException      Rethrown key generation or retrieval exception
     */
    @NonNull
    @RequiresApi(M)
    @SuppressWarnings("unused")
    public static EncryptionCompat newInstance() {
        return new EncryptionCompat(null, null, new Api23Encryption());
    }
}
