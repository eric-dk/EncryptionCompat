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

package com.encryptioncompat.internal

import android.content.Context
import android.os.Build
import android.util.SparseArray
import androidx.core.util.contains
import com.encryptioncompat.internal.keyholder.IceCreamSandwichKeyHolder
import com.encryptioncompat.internal.keyholder.JellyBeanKeyHolder
import com.encryptioncompat.internal.keyholder.MarshmallowKeyHolder
import com.encryptioncompat.internal.keyholder.PieKeyHolder
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.withContext
import java.nio.ByteBuffer
import java.util.concurrent.Executors
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec

internal class Encryption(context: Context, sdkRange: IntRange) {
    private companion object {
        val SHARED = Executors.newSingleThreadExecutor().asCoroutineDispatcher()
    }

    private val sdkToKeyHolders = SparseArray<KeyHolder>(4)
        .apply {
            if (sdkRange.first < Build.VERSION_CODES.JELLY_BEAN_MR2) {
                put(Build.VERSION_CODES.ICE_CREAM_SANDWICH, IceCreamSandwichKeyHolder(context))
            }
            if (sdkRange.contains(Build.VERSION_CODES.JELLY_BEAN_MR2)) {
                put(Build.VERSION_CODES.JELLY_BEAN_MR2, JellyBeanKeyHolder(context))
            }
            if (sdkRange.contains(Build.VERSION_CODES.M)) {
                put(Build.VERSION_CODES.M, MarshmallowKeyHolder(context))
            }
            if (sdkRange.contains(Build.VERSION_CODES.P) && context.packageManager.hasStrongBox()) {
                put(Build.VERSION_CODES.P, PieKeyHolder(context))
            }
        }

    private val cipher by lazy { Cipher.getInstance("AES/CBC/PKCS5Padding") }

    suspend fun encrypt(input: String): String {
        input.isNotEmpty() || return input

        // Iterate available keys
        return withContext(SHARED) {
            for (sdk in sdkToKeyHolders.reverseKeyIterator()) {
                try {
                    return@withContext encrypt(sdk, input)
                } catch (throwable: Throwable) {
                    throwable.printStackTrace()
                }
            }
            throw IllegalStateException("Cannot generate key")
        }
    }

    suspend fun decrypt(input: String): String {
        input.isNotEmpty() || return input

        // Segment input
        return withContext(SHARED) {
            val buffer = input.decode()

            val sdk = buffer.get().toInt()
            val iv = ByteArray(16).apply { buffer.get(this) }
            val text = ByteArray(buffer.int).apply { buffer.get(this) }
            val metadata = ByteArray(buffer.int).apply { buffer.get(this) }

            decrypt(sdk, iv, text, metadata)
        }
    }

    private fun encrypt(sdk: Int, input: String): String {
        // Initialize cipher
        val bundle = sdkToKeyHolders[sdk].getEncryptBundle()
        cipher.init(Cipher.ENCRYPT_MODE, bundle.key)

        val iv = cipher.iv
        val text = cipher.doFinal(input.toByteArray())
        return ByteBuffer.allocate(25 + text.size + bundle.metadata.size)
            .put(sdk.toByte())
            .put(iv)
            .putInt(text.size)
            .put(text)
            .putInt(bundle.metadata.size)
            .put(bundle.metadata)
            .encode()
    }

    private fun decrypt(sdk: Int, iv: ByteArray, text: ByteArray, metadata: ByteArray): String {
        // Choose keys
        sdkToKeyHolders.contains(sdk) || throw IllegalStateException("Cannot retrieve key")

        val key = sdkToKeyHolders[sdk].getDecryptKey(metadata)
        cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(iv))
        return String(cipher.doFinal(text))
    }
}
