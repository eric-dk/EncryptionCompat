package com.encryptioncompat

import androidx.test.ext.junit.runners.AndroidJUnit4
import com.encryptioncompat.internal.decodeBase64
import com.encryptioncompat.internal.encodeBase64
import com.encryptioncompat.internal.use
import com.google.common.truth.Truth.assertThat
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ExtensionTest {
    @Test
    fun encode_decode_matches() {
        val expected = byteArrayOf(1, 2, 3)
        val result = expected.encodeBase64().decodeBase64()
        assertThat(result).isEqualTo(expected)
    }

    @Test
    fun use_securely_wipes() {
        val result = byteArrayOf(0, 0, 0)
        result.use { it.fill(1) }
        assertThat(result).isNotEqualTo(byteArrayOf(0, 0, 0))
        assertThat(result).isNotEqualTo(byteArrayOf(1, 1, 1))
    }
}
