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
 * Preferred key mode depends on platform version and successful
 * key generation - may fallback to a legacy mode. Preferred cipher
 * mode solely depends on platform version. Legacy key and cipher
 * modes depend on `minSdk`; for compatibility purposes, you may
 * specify `0` to load all legacy modes. Each message contains the
 * key and cipher mode used in encryption, thus preserving
 * backwards-compatibility for decryption.
 *
 * @param context           Will get application context
 * @param minSdk            Minimum API level
 */
class EncryptionCompat(context: Context, minSdk: Int) {
    interface Callback {
        fun onSuccess(output: String)
        fun onFailure(throwable: Throwable)
    }

    private val encryption = Encryption(context.applicationContext, minSdk..Build.VERSION.SDK_INT)

    //region Encrypt
    /**
     * Encrypts {@code message}. Can be called from any context;
     * encryption is run on independent thread.
     *
     * @param message       Message to encrypt
     * @return              Encrypted message
     * @since 3.0.0
     */
    @CheckResult
    suspend fun encrypt(message: String) = encryption.encrypt(message)

    /**
     * Encrypts {@code message}. Can be called from any context;
     * encryption is run on independent thread, callback on main.
     *
     * @param message       Message to encrypt
     * @param callback      Callback with encrypted message
     * @since 3.0.0
     */
    @AnyThread
    fun encrypt(callback: Callback, message: String) {
        val handler = CoroutineExceptionHandler { _, throwable -> callback.onFailure(throwable) }
        CoroutineScope(Dispatchers.Main + SupervisorJob()).launch(handler) {
            callback.onSuccess(encrypt(message))
        }
    }
    //endregion

    //region Decrypt
    /**
     * Decrypts {@code message}. Will throw exception if mode unsupported or key unavailable.
     * Can be called from any thread; encryption is run on independent thread.
     *
     * @param message       Message to decrypt
     * @return              Decrypted message
     * @since 3.0.0
     */
    @CheckResult
    suspend fun decrypt(message: String) = encryption.decrypt(message)

    /**
     * Decrypts {@code message}. Will throw exception if encoded mode unsupported or key unavailable.
     * Can be called from any thread; encryption is run on independent thread, callback on main.
     *
     * @param message       Message to decrypt
     * @param callback      Callback with decrypted message
     * @since 3.0.0
     */
    @AnyThread
    fun decrypt(callback: Callback, message: String) {
        val handler = CoroutineExceptionHandler { _, throwable -> callback.onFailure(throwable) }
        CoroutineScope(Dispatchers.Main + SupervisorJob()).launch(handler) {
            callback.onSuccess(decrypt(message))
        }
    }
    //endregion
}
