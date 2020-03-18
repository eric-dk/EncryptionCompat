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

import com.encryptioncompat.internal.CipherHolder
import com.encryptioncompat.internal.use
import java.nio.ByteBuffer
import java.security.Key
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec

internal class BaseCipherHolder : CipherHolder {
    // PKCS5 for compatibility; interchangeable with PKCS7
    private val cipher by lazy { Cipher.getInstance("AES/CBC/PKCS5Padding") }
    private val hmac by lazy { Mac.getInstance("HmacSHA256") }

    override fun encrypt(key: Key, input: ByteArray, aad: ByteArray): ByteArray {
        cipher.init(Cipher.ENCRYPT_MODE, key)
        hmac.init(key)

        // Must use cipher generated IV
        cipher.iv.use { iv ->
            cipher.doFinal(input).use { text ->
                hmac.update(iv)
                hmac.update(text)
                hmac.update(aad)
                hmac.doFinal().use { mac ->
                    return ByteBuffer.allocate(mac.size + iv.size + text.size)
                        .put(mac)
                        .put(iv)
                        .put(text)
                        .array()
                }
            }
        }
    }

    override fun decrypt(key: Key, input: ByteBuffer, aad: ByteBuffer): ByteArray {
        hmac.init(key)

        // HMAC-SHA256 produces 256 bit mac
        ByteArray(32).use { mac ->
            input[mac]
            // CBC IV is AES block size
            ByteArray(16).use { iv ->
                input[iv]
                ByteArray(input.remaining()).use { text ->
                    input[text]
                    hmac.update(iv)
                    hmac.update(text)
                    hmac.update(aad)

                    if (!MessageDigest.isEqual(mac, hmac.doFinal())) {
                        throw IllegalStateException("Cannot authenticate")
                    }

                    cipher.init(Cipher.DECRYPT_MODE, key, IvParameterSpec(iv))
                    return cipher.doFinal(text)
                }
            }
        }
    }
}
