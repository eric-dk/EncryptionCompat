/*
 * Copyright © 2024 Eric Nguyen
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
import android.os.Build
import com.encryptioncompat.EncryptionCompat
import kotlinx.coroutines.rx3.rxSingle

/**
 * Preferred key mode depends on platform version and successful
 * key generation - may fallback to a legacy mode. Preferred cipher
 * mode solely depends on platform version. Legacy key and cipher
 * modes depend on `minSdk`; for compatibility purposes, you may
 * specify `0` to load all legacy modes. Each message contains the
 * key and cipher mode used in encryption, thus preserving
 * backwards-compatibility for decryption.
 *
 * @param context           Context
 * @param sdkRange          Target API levels
 */
class RxEncryptionCompat(context: Context, sdkRange: IntRange) {
    private val encryption = EncryptionCompat(context, sdkRange)

    @JvmOverloads
    constructor(context:Context,
                minSdk: Int,
                maxSdk: Int = Build.VERSION.SDK_INT) : this(context, minSdk..maxSdk)

    /**
     * Encrypts {@code message}. Key management depends on device support.
     *
     * @param message       Message to encrypt
     * @return              Single with encrypted message
     * @since 3.0.0
     */
    fun encrypt(message: String) = rxSingle { encryption.encrypt(message) }

    /**
     * Decrypts {@code input}. Will pass error if mode unsupported or key unavailable.
     *
     * @param message       Message to decrypt
     * @return              Single with decrypted message
     * @since 3.0.0
     */
    fun decrypt(message: String) = rxSingle { encryption.decrypt(message) }
}
