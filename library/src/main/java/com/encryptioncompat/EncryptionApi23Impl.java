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

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.util.Base64;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import javax.crypto.KeyGenerator;
import static android.os.Build.VERSION_CODES.M;
import static android.util.Base64.DEFAULT;

@RequiresApi(M)
class EncryptionApi23Impl extends EncryptionBaseImpl {
    private static final String KEY_PROVIDER = "AndroidKeyStore";
    private static final String MASTER_KEY   = EncryptionApi23Impl.class.getSimpleName();

    private final Key key;

    private EncryptionApi23Impl() {
        try {
            key = getKey();
        } catch (GeneralSecurityException | IOException e) {
            throw new EncryptionException(e);
        }
    }

    private Key getKey() throws GeneralSecurityException, IOException {
        KeyStore keyStore = KeyStore.getInstance(KEY_PROVIDER);
        keyStore.load(null);

        Key result = keyStore.getKey(MASTER_KEY, null);
        if (result == null) {
            KeyGenerator generator = KeyGenerator.getInstance(KEY_ALGORITHM, KEY_PROVIDER);
            KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(MASTER_KEY,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .setKeySize(KEY_SIZE)
                    .build();

            generator.init(spec);
            result = generator.generateKey();
        }
        return result;
    }

    static EncryptionApi23Impl get() {
        return Holder.SINGLETON;
    }

    String encrypt(String data) {
        return encrypt(key, data.getBytes());
    }

    String decrypt(String data) {
        String[] fields = data.split(FIELD_SEPARATOR);
        if (fields.length != 2) {
            throw new EncryptionException("Invalid format");
        }

        byte[] iv = Base64.decode(fields[0], DEFAULT);
        byte[] cipherText = Base64.decode(fields[1], DEFAULT);
        return decrypt(key, iv, cipherText);
    }

    private static final class Holder {
        private static final EncryptionApi23Impl SINGLETON = new EncryptionApi23Impl();
    }
}
