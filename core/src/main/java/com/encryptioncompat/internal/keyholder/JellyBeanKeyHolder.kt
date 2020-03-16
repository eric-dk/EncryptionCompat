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
import android.os.Build
import android.security.KeyPairGeneratorSpec
import com.encryptioncompat.internal.KeyBundle
import com.encryptioncompat.internal.KeyHolder
import com.encryptioncompat.internal.appName
import java.math.BigInteger
import java.security.*
import java.util.*
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.security.auth.x500.X500Principal

@TargetApi(Build.VERSION_CODES.JELLY_BEAN_MR2)
internal class JellyBeanKeyHolder(context: Context) : KeyHolder {
    private val keyAlias = "${context.appName}-JB"
    private val keySpec = KeyPairGeneratorSpec.Builder(context)
        .setAlias(keyAlias)
        .setSerialNumber(BigInteger.ONE)
        .setSubject(X500Principal("CN=$keyAlias CA Certificate"))
        .setStartDate(Calendar.getInstance().time)
        .setEndDate(Calendar.getInstance().apply { add(Calendar.YEAR, 20) }.time)
        .build()

    private val cipher by lazy { Cipher.getInstance("RSA/NONE/PKCS1Padding") }
    private val storedKey by lazy {
        val store = KeyStore.getInstance(KeyHolder.PROVIDER)
        store.load(null)
        store.getCertificate(keyAlias)
            // Existing key
            ?.let { certificate ->
                store.getKey(keyAlias, null)?.let { key ->
                    (key as? PrivateKey)?.let { KeyPair(certificate.publicKey, it) }
                }
            }
            // Generate key
            ?: KeyPairGenerator.getInstance("RSA", KeyHolder.PROVIDER)
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

    override fun getDecryptKey(metadata: ByteArray): Key {
        cipher.init(Cipher.UNWRAP_MODE, storedKey.private)
        return cipher.unwrap(metadata, KeyHolder.AES, Cipher.SECRET_KEY)
    }
}
