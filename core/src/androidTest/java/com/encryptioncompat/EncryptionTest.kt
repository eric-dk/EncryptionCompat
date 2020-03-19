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

package com.encryptioncompat

import android.content.Context
import android.os.Build.VERSION.SDK_INT
import android.os.Build.VERSION_CODES.*
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import com.encryptioncompat.internal.Encryption
import com.encryptioncompat.internal.decodeBase64
import com.encryptioncompat.internal.encodeBase64
import com.encryptioncompat.internal.hasStrongBox
import com.google.common.truth.Truth.assertThat
import kotlinx.coroutines.runBlocking
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.nio.ByteBuffer

@RunWith(AndroidJUnit4::class)
class EncryptionTest {
    private lateinit var context: Context

    @Before
    fun setup() {
        context = ApplicationProvider.getApplicationContext()
    }

    @Test
    fun empty_encrypt_returns_empty() {
        val result = runBlocking {
            Encryption(context, BASE..SDK_INT).encrypt("")
        }
        assertThat(result).isEmpty()
    }

    @Test
    fun empty_decrypt_returns_empty() {
        val result = runBlocking {
            Encryption(context, BASE..SDK_INT).decrypt("")
        }
        assertThat(result).isEmpty()
    }

    @Test
    fun base_flags_set() {
        val ciphertext = runBlocking {
            Encryption(context, BASE until JELLY_BEAN_MR2).encrypt("foo")
        }

        val result = ByteBuffer.wrap(ciphertext.decodeBase64())
        assertThat(result[0]).isEqualTo(BASE)
        assertThat(result[1]).isEqualTo(BASE)
    }

    @Test
    fun base_encrypt_decrypt_matches() {
        val encryption = Encryption(context, BASE until JELLY_BEAN_MR2)
        val expected = "foo"

        val result = runBlocking {
            encryption.decrypt(encryption.encrypt(expected))
        }
        assertThat(result).isEqualTo(expected)
    }

    @SdkSuppress(minSdkVersion = JELLY_BEAN_MR2)
    @Test
    fun jelly_bean_flags_set() {
        val ciphertext = runBlocking {
            Encryption(context, JELLY_BEAN_MR2 until LOLLIPOP).encrypt("foo")
        }

        val result = ByteBuffer.wrap(ciphertext.decodeBase64())
        assertThat(result[0]).isEqualTo(JELLY_BEAN_MR2)
        assertThat(result[1]).isEqualTo(BASE)
    }

    @SdkSuppress(minSdkVersion = JELLY_BEAN_MR2)
    @Test
    fun jelly_bean_encrypt_decrypt_matches() {
        val encryption = Encryption(context, JELLY_BEAN_MR2 until LOLLIPOP)
        val expected = "foo"

        val result = runBlocking {
            encryption.decrypt(encryption.encrypt(expected))
        }
        assertThat(result).isEqualTo(expected)
    }

    @SdkSuppress(minSdkVersion = LOLLIPOP)
    @Test
    fun lollipop_flags_set() {
        val ciphertext = runBlocking {
            Encryption(context, JELLY_BEAN_MR2 until M).encrypt("foo")
        }

        val result = ByteBuffer.wrap(ciphertext.decodeBase64())
        assertThat(result[0]).isEqualTo(JELLY_BEAN_MR2)
        assertThat(result[1]).isEqualTo(LOLLIPOP)
    }

    @SdkSuppress(minSdkVersion = LOLLIPOP)
    @Test
    fun lollipop_encrypt_decrypt_matches() {
        val encryption = Encryption(context, JELLY_BEAN_MR2 until M)
        val expected = "foo"

        val result = runBlocking {
            encryption.decrypt(encryption.encrypt(expected))
        }
        assertThat(result).isEqualTo(expected)
    }

    @SdkSuppress(minSdkVersion = M)
    @Test
    fun marshmallow_flags_set() {
        val ciphertext = runBlocking {
            Encryption(context, M until P).encrypt("foo")
        }

        val result = ByteBuffer.wrap(ciphertext.decodeBase64())
        assertThat(result[0]).isEqualTo(M)
        assertThat(result[1]).isEqualTo(LOLLIPOP)
    }

    @SdkSuppress(minSdkVersion = M)
    @Test
    fun marshmallow_encrypt_decrypt_matches() {
        val encryption = Encryption(context, M until P)
        val expected = "foo"

        val result = runBlocking {
            encryption.decrypt(encryption.encrypt(expected))
        }
        assertThat(result).isEqualTo(expected)
    }

    @SdkSuppress(minSdkVersion = P)
    @Test
    fun pie_flag_set() {
        assumeTrue(context.hasStrongBox())
        val ciphertext = runBlocking {
            Encryption(context, P..SDK_INT).encrypt("foo")
        }

        val result = ByteBuffer.wrap(ciphertext.decodeBase64())
        assertThat(result[0]).isEqualTo(P)
        assertThat(result[1]).isEqualTo(LOLLIPOP)
    }

    @SdkSuppress(minSdkVersion = P)
    @Test
    fun pie_encrypt_decrypt_matches() {
        val encryption = Encryption(context, P..SDK_INT)
        val expected = "foo"

        val result = runBlocking {
            encryption.decrypt(encryption.encrypt(expected))
        }
        assertThat(result).isEqualTo(expected)
    }

    @Test(expected = IllegalStateException::class)
    fun unsupported_flags_throw() {
        val ciphertext = ByteBuffer.allocate(16)
            .put(P.toByte())
            .put(LOLLIPOP.toByte())
            .array()
            .encodeBase64()
        runBlocking {
            Encryption(context, BASE until JELLY_BEAN_MR2).decrypt(ciphertext)
        }
    }
}
