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
import android.os.Build
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.SdkSuppress
import com.encryptioncompat.internal.Encryption
import com.encryptioncompat.internal.decode
import com.encryptioncompat.internal.encode
import com.encryptioncompat.internal.hasStrongBox
import com.google.common.truth.Truth.assertThat
import kotlinx.coroutines.runBlocking
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.nio.ByteBuffer
import kotlin.math.min

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
            val range = Build.VERSION_CODES.BASE..Build.VERSION.SDK_INT
            Encryption(context, range).encrypt("")
        }
        assertThat(result).isEmpty()
    }

    @Test
    fun empty_decrypt_returns_empty() {
        val result = runBlocking {
            val range = Build.VERSION_CODES.BASE..Build.VERSION.SDK_INT
            Encryption(context, range).decrypt("")
        }
        assertThat(result).isEmpty()
    }

    @Test
    fun ice_cream_sandwich_flag_set() {
        val expected = Build.VERSION_CODES.ICE_CREAM_SANDWICH
        val result = runBlocking {
            val range = Build.VERSION_CODES.BASE..Build.VERSION_CODES.JELLY_BEAN_MR1
            Encryption(context, range).encrypt("foo").decode().get().toInt()
        }
        assertThat(result).isEqualTo(expected)
    }

    @SdkSuppress(minSdkVersion = Build.VERSION_CODES.JELLY_BEAN_MR2)
    @Test
    fun jelly_bean_flag_set() {
        val expected = Build.VERSION_CODES.JELLY_BEAN_MR2
        val result = runBlocking {
            val range = Build.VERSION_CODES.JELLY_BEAN_MR2..Build.VERSION_CODES.LOLLIPOP_MR1
            Encryption(context, range).encrypt("foo").decode().get().toInt()
        }
        assertThat(result).isEqualTo(expected)
    }

    @Test(expected = IllegalStateException::class)
    fun jelly_bean_flag_unsupported() {
        runBlocking {
            val buffer = ByteBuffer.allocate(25).putInt(Build.VERSION_CODES.JELLY_BEAN_MR2)
            val range = Build.VERSION_CODES.BASE..Build.VERSION_CODES.JELLY_BEAN_MR1
            Encryption(context, range).decrypt(buffer.encode())
        }
    }

    @SdkSuppress(minSdkVersion = Build.VERSION_CODES.M)
    @Test
    fun marshmallow_flag_set() {
        assumeTrue(!context.packageManager.hasStrongBox())
        val expected = Build.VERSION_CODES.M
        val result = runBlocking {
            val range = Build.VERSION_CODES.M..Build.VERSION_CODES.O_MR1
            Encryption(context, range).encrypt("foo").decode().get().toInt()
        }
        assertThat(result).isEqualTo(expected)
    }


    @Test(expected = IllegalStateException::class)
    fun marshmallow_flag_unsupported() {
        runBlocking {
            val buffer = ByteBuffer.allocate(25).putInt(Build.VERSION_CODES.M)
            val max = min(Build.VERSION.SDK_INT, Build.VERSION_CODES.LOLLIPOP_MR1)
            val range = Build.VERSION_CODES.BASE..max
            Encryption(context, range).decrypt(buffer.encode())
        }
    }

    @SdkSuppress(minSdkVersion = Build.VERSION_CODES.P)
    @Test
    fun pie_flag_set() {
        assumeTrue(context.packageManager.hasStrongBox())
        val expected = Build.VERSION_CODES.P
        val result = runBlocking {
            val range = Build.VERSION_CODES.P..Build.VERSION.SDK_INT
            Encryption(context, range).encrypt("foo").decode().get().toInt()
        }
        assertThat(result).isEqualTo(expected)
    }

    @Test(expected = IllegalStateException::class)
    fun pie_flag_unsupported() {
        runBlocking {
            val buffer = ByteBuffer.allocate(25).putInt(Build.VERSION_CODES.P)
            val max = min(Build.VERSION.SDK_INT, Build.VERSION_CODES.O_MR1)
            val range = Build.VERSION_CODES.BASE..max
            Encryption(context, range).decrypt(buffer.encode())
        }
    }

    @Test
    fun encrypt_decrypt_matches() {
        val expected = "foo"
        val result = runBlocking {
            val encryption = Encryption(context, Build.VERSION_CODES.BASE..Build.VERSION.SDK_INT)
            encryption.decrypt(encryption.encrypt(expected))
        }
        assertThat(result).isEqualTo(expected)
    }
}
