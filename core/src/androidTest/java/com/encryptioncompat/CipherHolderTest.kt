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

package com.encryptioncompat

import android.os.Build.VERSION_CODES.LOLLIPOP
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import com.encryptioncompat.internal.KeyHolder
import com.encryptioncompat.internal.cipherholder.BaseCipherHolder
import com.encryptioncompat.internal.cipherholder.LollipopCipherHolder
import com.google.common.truth.Truth.assertThat
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.nio.ByteBuffer
import java.security.Key
import javax.crypto.KeyGenerator

@RunWith(AndroidJUnit4::class)
class CipherHolderTest {
    private lateinit var key: Key

    @Before
    fun setup() {
        key = KeyGenerator.getInstance(KeyHolder.AES)
            .apply { init(KeyHolder.LENGTH) }
            .generateKey()
    }

    @Test
    fun base_no_exceptions_on_instantiation() {
        val result = kotlin.runCatching { BaseCipherHolder() }
        assertThat(result.isSuccess).isTrue()
    }

    @Test
    fun base_encrypt_decrypt_matches() {
        val cipher = BaseCipherHolder()
        val expected = "foo"

        val ciphertext = cipher.encrypt(key, expected.toByteArray())
        val plaintext = cipher.decrypt(key, ByteBuffer.wrap(ciphertext))

        val result = String(plaintext)
        assertThat(result).isEqualTo(expected)
    }

    @SdkSuppress(minSdkVersion = LOLLIPOP)
    @Test
    fun lollipop_no_exceptions_on_instantiation() {
        val result = kotlin.runCatching { LollipopCipherHolder() }
        assertThat(result.isSuccess).isTrue()
    }

    @SdkSuppress(minSdkVersion = LOLLIPOP)
    @Test
    fun lollipop_encrypt_decrypt_matches() {
        val cipher = LollipopCipherHolder()
        val expected = "foo"

        val ciphertext = cipher.encrypt(key, expected.toByteArray())
        val plaintext = cipher.decrypt(key, ByteBuffer.wrap(ciphertext))

        val result = String(plaintext)
        assertThat(result).isEqualTo(expected)
    }
}
