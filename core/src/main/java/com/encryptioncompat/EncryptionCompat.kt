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

package com.encryptioncompat

import android.content.Context
import android.os.Build
import androidx.annotation.AnyThread
import androidx.annotation.CheckResult
import com.encryptioncompat.internal.Encryption
import kotlinx.coroutines.*

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
class EncryptionCompat(context: Context, minSdk: Int) {
    interface Callback {
        fun onSuccess(output: String)
        fun onFailure(throwable: Throwable)
    }

    private val encryption = Encryption(context.applicationContext, minSdk..Build.VERSION.SDK_INT)

    //region Encrypt
    /**
     * Encrypts {@code input}. Key management depends on device support.
     * Can be called from any thread; encryption is run on independent thread, callback on main.
     *
     * @param input         String to encrypt
     * @param callback      Callback on execution
     * @since 3.0.0
     */
    @AnyThread
    fun encrypt(callback: Callback, input: String) {
        val handler = CoroutineExceptionHandler { _, throwable -> callback.onFailure(throwable) }
        CoroutineScope(Dispatchers.Main + SupervisorJob()).launch(handler) {
            callback.onSuccess(encrypt(input))
        }
    }

    /**
     * Encrypts {@code input}. Key management depends on device support.
     * Can be called from any thread; encryption is run on independent thread.
     *
     * @param input         String to encrypt
     * @return              Encrypted string
     * @since 3.0.0
     */
    @CheckResult
    suspend fun encrypt(input: String) = encryption.encrypt(input)
    //endregion

    //region Decrypt
    /**
     * Decrypts {@code input}. Will throw exception if encoded mode unsupported or key unavailable.
     * Can be called from any thread; encryption is run on independent thread, callback on main.
     *
     * @param input         String to decrypt
     * @param callback      Callback on execution
     * @since 3.0.0
     */
    @AnyThread
    fun decrypt(callback: Callback, input: String) {
        val handler = CoroutineExceptionHandler { _, throwable -> callback.onFailure(throwable) }
        CoroutineScope(Dispatchers.Main + SupervisorJob()).launch(handler) {
            callback.onSuccess(decrypt(input))
        }
    }

    /**
     * Decrypts {@code input}. Will throw exception if mode unsupported or key unavailable.
     * Can be called from any thread; encryption is run on independent thread.
     *
     * @param input         String to decrypt
     * @return              Decrypted string
     * @since 3.0.0
     */
    @CheckResult
    suspend fun decrypt(input: String) = encryption.decrypt(input)
    //endregion
}
