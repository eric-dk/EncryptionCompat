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

@file:Suppress("Deprecation")
package com.encryptioncompat.internal.keyholder

import android.annotation.TargetApi
import android.content.Context
import android.os.Build.VERSION_CODES.JELLY_BEAN_MR2
import android.security.KeyPairGeneratorSpec
import com.encryptioncompat.internal.KeyBundle
import com.encryptioncompat.internal.KeyHolder
import com.encryptioncompat.internal.getKeyPair
import java.math.BigInteger
import java.security.Key
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.security.auth.x500.X500Principal

/**
 * Stores RSA key in Android Keystore, wraps and unwraps per-message AES key.
 *
 * @param context       Application context
 */
@TargetApi(JELLY_BEAN_MR2)
internal class JellyBeanKeyHolder(context: Context) : KeyHolder {
    override val keyAlias = "${context.packageName}-ECJ"

    // Key good until 2048-1-1
    private val keySpec = KeyPairGeneratorSpec.Builder(context)
        .setAlias(keyAlias)
        .setSerialNumber(BigInteger.ONE)
        .setSubject(X500Principal("CN=fake"))
        .setStartDate(Date(0L))
        .setEndDate(Date(2461449600000L))
        .build()

    // ECB for compatibility; unused
    private val cipher by lazy { Cipher.getInstance("RSA/ECB/PKCS1Padding") }
    private val storedKey by lazy {
        val store = KeyStore.getInstance(KeyHolder.STORE)
        store.load(null)
        store.getKeyPair(keyAlias)
            ?: KeyPairGenerator.getInstance("RSA", KeyHolder.STORE)
                .apply { initialize(keySpec) }
                .genKeyPair()
    }
    private val wrappedKey by lazy {
        KeyGenerator.getInstance(KeyHolder.AES)
            .apply { init(KeyHolder.LENGTH) }
            .generateKey()
    }

    override fun getEncryptBundle(): KeyBundle {
        cipher.init(Cipher.WRAP_MODE, storedKey.public)
        return KeyBundle(wrappedKey, cipher.wrap(wrappedKey))
    }

    override fun getDecryptKey(supplement: ByteArray): Key {
        cipher.init(Cipher.UNWRAP_MODE, storedKey.private)
        return cipher.unwrap(supplement, KeyHolder.AES, Cipher.SECRET_KEY)
    }
}
