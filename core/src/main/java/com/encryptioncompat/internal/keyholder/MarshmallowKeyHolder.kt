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

package com.encryptioncompat.internal.keyholder

import android.annotation.TargetApi
import android.content.Context
import android.os.Build.VERSION_CODES.M
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.encryptioncompat.internal.KeyHolder

/**
 * Generates, stores, and retrieves global AES key from Android Keystore.
 */
@TargetApi(M)
internal class MarshmallowKeyHolder(context: Context) : AesKeyHolder() {
    override val keyAlias = "${context.packageName}-ECM"
    override val keySpec = KeyGenParameterSpec
        .Builder(keyAlias, KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_ENCRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
        .setKeySize(KeyHolder.LENGTH)
        .build()
}
