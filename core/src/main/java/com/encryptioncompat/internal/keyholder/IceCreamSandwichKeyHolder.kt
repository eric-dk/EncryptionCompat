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

import android.content.Context
import androidx.core.content.edit
import com.encryptioncompat.internal.KeyBundle
import com.encryptioncompat.internal.KeyHolder
import java.security.Key
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

internal class IceCreamSandwichKeyHolder(context: Context) : KeyHolder {
    private companion object {
        const val NAME = "EC-ICS"
    }

    private val secureRandom = SecureRandom()
    private val sharedPreferences = context.getSharedPreferences(NAME, Context.MODE_PRIVATE)

    private val keyFactory by lazy { SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1") }
    private val password by lazy {
        sharedPreferences.getString(NAME, null)
            ?.toCharArray()
            ?: run {
                // Generate password
                val bytes = ByteArray(64)
                secureRandom.nextBytes(bytes)

                val string = String(bytes)
                sharedPreferences.edit { putString(NAME, string) }
                string.toCharArray()
            }
    }

    override fun getEncryptBundle(): KeyBundle {
        val salt = ByteArray(KeyHolder.LENGTH / 8)
        secureRandom.nextBytes(salt)
        return KeyBundle(getKey(salt), salt)
    }

    override fun getDecryptKey(metadata: ByteArray) = getKey(metadata)

    private fun getKey(salt: ByteArray): Key {
        val spec = PBEKeySpec(password, salt, 10_000, KeyHolder.LENGTH)
        val key = keyFactory.generateSecret(spec).encoded
        return SecretKeySpec(key, KeyHolder.AES)
    }
}
