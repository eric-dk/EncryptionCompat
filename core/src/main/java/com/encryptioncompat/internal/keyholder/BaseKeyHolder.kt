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
import com.encryptioncompat.internal.Encryption
import com.encryptioncompat.internal.KeyBundle
import com.encryptioncompat.internal.KeyHolder
import com.encryptioncompat.internal.use
import java.security.Key
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Stores password in Shared Preferences; recreates per-message AES key from password and salt.
 *
 * @param context       Application context
 */
internal class BaseKeyHolder(context: Context) : KeyHolder {
    override val keyAlias = "${context.packageName}-EC1"
    private val sharedPreferences = context.getSharedPreferences(keyAlias, Context.MODE_PRIVATE)

    private val keyFactory by lazy { SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1") }
    private val password by lazy {
        val string = sharedPreferences.getString(keyAlias, null)
            // Generate 32 character password
            ?: ByteArray(32).use { bytes ->
                Encryption.RANDOM.nextBytes(bytes)
                String(bytes).also { sharedPreferences.edit { putString(keyAlias, it) } }
            }
        string.toCharArray()
    }

    override fun getEncryptBundle(): KeyBundle {
        // Generate salt
        val salt = ByteArray(KeyHolder.LENGTH / 8)
        Encryption.RANDOM.nextBytes(salt)
        return KeyBundle(getKey(salt), salt)
    }

    override fun getDecryptKey(supplement: ByteArray) = getKey(supplement)

    private fun getKey(salt: ByteArray): Key {
        val spec = PBEKeySpec(password, salt, 10_000, KeyHolder.LENGTH)
        val key = keyFactory.generateSecret(spec).encoded

        // Transcode with initialized IV
        return SecretKeySpec(key, KeyHolder.AES)
    }
}
