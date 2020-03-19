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

package com.encryptioncompat.internal.cipherholder

import android.annotation.TargetApi
import android.os.Build.VERSION_CODES.LOLLIPOP
import com.encryptioncompat.internal.CipherHolder
import com.encryptioncompat.internal.use
import java.nio.ByteBuffer
import java.security.Key
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec

@TargetApi(LOLLIPOP)
internal class LollipopCipherHolder : CipherHolder {
    private val cipher by lazy { Cipher.getInstance("AES/GCM/NoPadding") }

    override fun encrypt(key: Key, plaintext: ByteArray, aad: ByteArray): ByteArray {
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(aad)

        // Must use cipher generated IV
        cipher.iv.use { iv ->
            cipher.doFinal(plaintext).use { text ->
                // Serialize segments into cipher data:
                // [iv length][contents]
                return ByteBuffer.allocate(1 + iv.size + text.size)
                    .put(iv.size.toByte())
                    .put(iv)
                    .put(text)
                    .array()
            }
        }
    }

    override fun decrypt(key: Key, ciphertext: ByteBuffer, aad: ByteBuffer): ByteArray {
        val ivSize = ciphertext.get().toInt()
        ivSize in 12..16 || throw IllegalStateException("Cannot authenticate")

        // GCM IV is 12-16 bytes
        ByteArray(ivSize).use { iv ->
            ciphertext[iv]
            ByteArray(ciphertext.remaining()).use { text ->
                // Deserialize cipher data into segments
                // [iv length][contents]
                ciphertext[text]
                cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
                cipher.updateAAD(aad)
                return cipher.doFinal(text)
            }
        }
    }
}
