/*
 * Copyright © 2020 Eric Nguyen
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

@file:Suppress("Unused")
package com.encryptioncompat.rx

import android.content.Context
import com.encryptioncompat.EncryptionCompat
import kotlinx.coroutines.rx2.rxSingle

class RxEncryptionCompat(context: Context, minSdk: Int) {
    private val encryption = EncryptionCompat(context, minSdk)

    /**
     * Encrypts {@code input} with AES-256, CBC, PKCS7-padded key.
     *
     * @param input         String to encrypt
     * @return              Single with encrypted string
     * @since 3.0.0
     */
    fun encrypt(input: String) = rxSingle { encryption.encrypt(input) }

    /**
     * Decrypts {@code input} according to encoded key mode.
     *
     * @param input         String to decrypt
     * @return              Single with decrypted string
     * @since 3.0.0
     */
    fun decrypt(input: String) = rxSingle { encryption.decrypt(input) }
}
