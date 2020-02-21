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
import com.encryptioncompat.internal.hasStrongBox
import com.encryptioncompat.internal.keyholder.IceCreamSandwichKeyHolder
import com.encryptioncompat.internal.keyholder.JellyBeanKeyHolder
import com.encryptioncompat.internal.keyholder.MarshmallowKeyHolder
import com.encryptioncompat.internal.keyholder.PieKeyHolder
import com.google.common.truth.Truth.assertThat
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class KeyHolderTest {
    private lateinit var context: Context

    @Before
    fun setup() {
        context = ApplicationProvider.getApplicationContext()
    }

    @Test
    fun ice_cream_sandwich_no_exceptions_on_instantiation() {
        val result = kotlin.runCatching { IceCreamSandwichKeyHolder(context) }
        assertThat(result.isSuccess).isTrue()
    }

    @Test
    fun ice_cream_sandwich_encrypt_key_has_metadata() {
        assertThat(IceCreamSandwichKeyHolder(context).getEncryptBundle().metadata).isNotEmpty()
    }

    @SdkSuppress(minSdkVersion = Build.VERSION_CODES.JELLY_BEAN_MR2)
    @Test
    fun jelly_bean_no_exceptions_on_instantiation() {
        val result = kotlin.runCatching { JellyBeanKeyHolder(context) }
        assertThat(result.isSuccess).isTrue()
    }

    @SdkSuppress(minSdkVersion = Build.VERSION_CODES.JELLY_BEAN_MR2)
    @Test
    fun jelly_bean_encrypt_key_has_metadata() {
        assertThat(JellyBeanKeyHolder(context).getEncryptBundle().metadata).isNotEmpty()
    }

    @SdkSuppress(minSdkVersion = Build.VERSION_CODES.M)
    @Test
    fun marshmallow_no_exceptions_on_instantiation() {
        val result = kotlin.runCatching { MarshmallowKeyHolder(context) }
        assertThat(result.isSuccess).isTrue()
    }

    @SdkSuppress(minSdkVersion = Build.VERSION_CODES.M)
    @Test
    fun marshmallow_encrypt_key_has_null_metadata() {
        assertThat(MarshmallowKeyHolder(context).getEncryptBundle().metadata).isNull()
    }

    @SdkSuppress(minSdkVersion = Build.VERSION_CODES.P)
    @Test
    fun pie_no_exceptions_on_instantiation() {
        val result = kotlin.runCatching { PieKeyHolder(context) }
        assertThat(result.isSuccess).isTrue()
    }

    @SdkSuppress(minSdkVersion = Build.VERSION_CODES.P)
    @Test
    fun pie_encrypt_key_has_null_metadata() {
        assumeTrue(context.packageManager.hasStrongBox())
        assertThat(PieKeyHolder(context).getEncryptBundle().metadata).isNull()
    }
}
