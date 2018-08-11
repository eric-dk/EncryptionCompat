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

import android.util.Base64;
import com.encryptioncompat.EncryptionException;
import java.security.GeneralSecurityException;
import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import static android.util.Base64.DEFAULT;
import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;

abstract class AbstractEncryption {
    static final int KEY_SIZE           = 256;
    static final String KEY_ALGORITHM   = "AES";

    static final Object LOCK            = new Object();
    static final String FIELD_SEPARATOR = "]";

    private final Cipher cipher;

    AbstractEncryption() {
        try {
            cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
        } catch (GeneralSecurityException e) {
            throw new EncryptionException(e);
        }
    }

    String encrypt(Key key, byte[] plainText) {
        byte[] iv;
        byte[] cipherText;
        try {
            synchronized (LOCK) {
                cipher.init(ENCRYPT_MODE, key);
                iv = cipher.getIV();
                cipherText = cipher.doFinal(plainText);
            }
        } catch (GeneralSecurityException e) {
            throw new EncryptionException(e);
        }

        String ivString = Base64.encodeToString(iv, DEFAULT);
        String encoded = Base64.encodeToString(cipherText, DEFAULT);
        return ivString + FIELD_SEPARATOR + encoded;
    }

    String decrypt(Key key, byte[] iv, byte[] cipherText) {
        byte[] plainText;
        try {
            synchronized (LOCK) {
                cipher.init(DECRYPT_MODE, key, new IvParameterSpec(iv));
                plainText = cipher.doFinal(cipherText);
            }
        } catch (GeneralSecurityException e) {
            throw new EncryptionException(e);
        }

        return new String(plainText);
    }
}
