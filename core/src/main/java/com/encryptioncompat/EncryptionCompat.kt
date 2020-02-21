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

class EncryptionCompat(context: Context, minSdk: Int) {
    interface Callback {
        fun onSuccess(output: String)
        fun onFailure(throwable: Throwable)
    }

    private val encryption = Encryption(context.applicationContext, minSdk..Build.VERSION.SDK_INT)

    /**
     * Encrypts {@code input} with AES-256, CBC, PKCS7-padded key.
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
     * Encrypts {@code input} with AES-256, CBC, PKCS7-padded key.
     *
     * @param input         String to encrypt
     * @return              Encrypted string
     * @since 3.0.0
     */
    @CheckResult
    suspend fun encrypt(input: String) = encryption.encrypt(input)

    /**
     * Decrypts {@code input} according to encoded key mode.
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
     * Decrypts {@code input} according to encoded key mode.
     *
     * @param input         String to decrypt
     * @return              Decrypted string
     * @since 3.0.0
     */
    @CheckResult
    suspend fun decrypt(input: String) = encryption.decrypt(input)
}
