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

package com.encryptioncompat.internal

import android.content.Context
import android.os.Build.VERSION_CODES.BASE
import android.os.Build.VERSION_CODES.JELLY_BEAN_MR2
import android.os.Build.VERSION_CODES.LOLLIPOP
import android.os.Build.VERSION_CODES.M
import android.os.Build.VERSION_CODES.P
import android.util.SparseArray
import com.encryptioncompat.internal.cipherholder.BaseCipherHolder
import com.encryptioncompat.internal.cipherholder.LollipopCipherHolder
import com.encryptioncompat.internal.keyholder.BaseKeyHolder
import com.encryptioncompat.internal.keyholder.JellyBeanKeyHolder
import com.encryptioncompat.internal.keyholder.MarshmallowKeyHolder
import com.encryptioncompat.internal.keyholder.PieKeyHolder
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.withContext
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.concurrent.Executors

/**
 * Internal engine; encompasses test configurations as well.
 *
 * @param context       Application context
 * @param sdkRange      Supported modes
 */
internal class Encryption(context: Context, sdkRange: IntRange) {
    companion object {
        // Serialize operations since Android Keystore is not thread-safe.
        private val FIFO = Executors.newSingleThreadExecutor().asCoroutineDispatcher()

        // Share random instance to prevent duplicate instantiation.
        val RANDOM by lazy { SecureRandom() }
    }

    init {
        if (sdkRange.first !in BASE..sdkRange.last) {
            throw IllegalArgumentException("Invalid SDK range")
        }
    }

    private val modeToCipherHolders = SparseArray<CipherHolder>(2).apply {
        if (sdkRange.first < LOLLIPOP) put(BASE, BaseCipherHolder())
        if (sdkRange.last >= LOLLIPOP) put(LOLLIPOP, LollipopCipherHolder())
    }
    private val modeToKeyHolders = SparseArray<KeyHolder>(4).apply {
        if (sdkRange.first < JELLY_BEAN_MR2) put(BASE, BaseKeyHolder(context))
        if (sdkRange.contains(JELLY_BEAN_MR2)) put(JELLY_BEAN_MR2, JellyBeanKeyHolder(context))
        if (sdkRange.contains(M)) put(M, MarshmallowKeyHolder(context))
        if (sdkRange.last >= P && context.hasStrongBox()) put(P, PieKeyHolder(context))
    }

    //region Encrypt
    suspend fun encrypt(message: String): String {
        message.isNotEmpty() || return message

        return withContext(FIFO) {
            // Always select highest cipher mode for encryption.
            val cipherMode = modeToCipherHolders.lastKey

            // Attempt to generate and store key, removing key modes that fail.
            for (keyMode in modeToKeyHolders.reverseKeyIterator()) {
                val modes = byteArrayOf(keyMode.toByte(), cipherMode.toByte())
                try {
                    val bundle = modeToKeyHolders[keyMode].getEncryptBundle()
                    return@withContext assemble(modes, bundle, message.toByteArray())
                } catch (exception: Exception) {
                    modeToKeyHolders.delete(keyMode)
                    continue
                }
            }
            throw IllegalStateException("Cannot generate key")
        }
    }

    private fun assemble(modes: ByteArray, bundle: KeyBundle, message: ByteArray): String {
        val cipherHolder = modeToCipherHolders[modes[1].toInt()]
        return cipherHolder.encrypt(bundle.key, message).use { ciphertext ->

            // Serialize segments into message:
            // [key mode][cipher mode][key supplement length][key supplement data][ciphertext]
            ByteBuffer.allocate(modes.size + 4 + bundle.supplement.size + ciphertext.size)
                .put(modes)
                .putInt(bundle.supplement.size)
                .put(bundle.supplement)
                .put(ciphertext)
                .array()
                .encodeBase64()
        }
    }
    //endregion

    //region Decrypt
    suspend fun decrypt(message: String): String {
        message.isNotEmpty() || return message

        return withContext(FIFO) {
            val buffer = ByteBuffer.wrap(message.decodeBase64())

            // Deserialize message into segments:
            // [key mode][cipher mode][key supplement length][key supplement data][ciphertext]
            val modes = buffer.duplicate().apply { limit(2) }
            buffer.position(2)
            val supplement = ByteArray(buffer.int).apply { buffer[this] }
            val data = buffer.slice()

            return@withContext disassemble(modes, data, supplement)
        }
    }

    private fun disassemble(modes: ByteBuffer, data: ByteBuffer, supplement: ByteArray): String {
        val keyHolder = modeToKeyHolders[modes[0].toInt()]
        val cipherHolder = modeToCipherHolders[modes[1].toInt()]

        // Can happen if minSdk is upped across a mode boundary.
        keyHolder ?: throw IllegalStateException("Cannot retrieve key")
        cipherHolder ?: throw IllegalStateException("Cannot retrieve cipher")

        val key = keyHolder.getDecryptKey(supplement)
        return String(cipherHolder.decrypt(key, data))
    }
    //endregion
}
