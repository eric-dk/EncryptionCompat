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

package com.encryptioncompat.internal.keyholder

import android.annotation.TargetApi
import android.os.Build.VERSION_CODES.M
import android.security.keystore.KeyGenParameterSpec
import com.encryptioncompat.internal.KeyBundle
import com.encryptioncompat.internal.KeyHolder
import java.security.Key
import java.security.KeyStore
import javax.crypto.KeyGenerator

/**
 * Generates, stores, and retrieves global AES key from Android Keystore.
 */
@TargetApi(M)
internal abstract class AesKeyHolder : KeyHolder {
    abstract val keySpec: KeyGenParameterSpec

    private val storedKey by lazy {
        val store = KeyStore.getInstance(KeyHolder.STORE)
        store.load(null)
        store.getKey(keyAlias, null)
            ?: KeyGenerator.getInstance(KeyHolder.AES, KeyHolder.STORE)
                .apply { init(keySpec) }
                .generateKey()
    }

    override fun getEncryptBundle() = KeyBundle(storedKey)

    override fun getDecryptKey(supplement: ByteArray): Key = storedKey
}
