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

package com.encryptioncompat.internal.keyholder

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.annotation.RequiresApi
import com.encryptioncompat.internal.KeyBundle
import com.encryptioncompat.internal.KeyHolder
import com.encryptioncompat.internal.appName
import java.security.Key
import java.security.KeyStore
import javax.crypto.KeyGenerator

@RequiresApi(Build.VERSION_CODES.P)
internal class PieKeyHolder(context: Context) : KeyHolder {
    private val keyAlias = "${context.appName}-P"
    private val keySpec = KeyGenParameterSpec
        .Builder(keyAlias, KeyProperties.PURPOSE_DECRYPT or KeyProperties.PURPOSE_ENCRYPT)
        .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
        .setKeySize(KeyHolder.LENGTH)
        .setIsStrongBoxBacked(true)
        .build()

    private val storedKey by lazy {
        val store = KeyStore.getInstance(KeyHolder.PROVIDER)
        store.load(null)
        store.getKey(keyAlias, null)
            ?: KeyGenerator.getInstance(KeyHolder.AES, KeyHolder.PROVIDER)
                .apply { init(keySpec) }
                .generateKey()
    }

    override fun getEncryptBundle() = KeyBundle(storedKey, ByteArray(0))

    override fun getDecryptKey(metadata: ByteArray): Key = storedKey
}
