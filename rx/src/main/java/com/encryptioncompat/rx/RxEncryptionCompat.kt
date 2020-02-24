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

/**
 * Encrypts with AES256/CBC/PKCS7 key, but the key management scheme depends on
 * device support:
 * <p><ul>
 * <li>Least secure (below API 18): Per-message key is created from random salt and global password
 * - stored in shared preferences
 * <li>More secure (API 18-22): Per-instance key is wrapped with global asymmetric key - saved in
 * Android Keystore
 * <li>Most secure (API 23+): Global key is managed by Android Keystore
 * <li>Most secure (API 28+): Same as above, but key is stored in hardware security module
 * </ul></p>
 * Due to manufacturer fragmentation, EncryptionCompat will attempt the highest possible scheme then
 * fall through until reaching the specified minimum platform.
 *
 * @param context           Will get application context
 * @param minSdk            Minimum supported platform
 */
class RxEncryptionCompat(context: Context, minSdk: Int) {
    private val encryption = EncryptionCompat(context, minSdk)

    /**
     * Encrypts {@code input}. Key management depends on device support.
     *
     * @param input         String to encrypt
     * @return              Single with encrypted string
     * @since 3.0.0
     */
    fun encrypt(input: String) = rxSingle { encryption.encrypt(input) }

    /**
     * Decrypts {@code input}. Will pass error if mode unsupported or key unavailable.
     *
     * @param input         String to decrypt
     * @return              Single with decrypted string
     * @since 3.0.0
     */
    fun decrypt(input: String) = rxSingle { encryption.decrypt(input) }
}
