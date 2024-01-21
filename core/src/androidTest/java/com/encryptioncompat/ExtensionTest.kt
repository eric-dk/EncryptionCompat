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
