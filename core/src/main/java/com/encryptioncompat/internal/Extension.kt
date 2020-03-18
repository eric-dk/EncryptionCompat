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

package com.encryptioncompat.internal

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build.VERSION.SDK_INT
import android.os.Build.VERSION_CODES.P
import android.util.Base64
import android.util.SparseArray
import androidx.core.util.size
import java.security.KeyPair
import java.security.KeyStore
import java.security.PrivateKey

internal fun ByteArray.encodeBase64() = Base64.encodeToString(this, Base64.DEFAULT)

// Overwrite with junk data after use; try-with-resources for byte arrays
internal inline fun <R> ByteArray.use(block: (ByteArray) -> R): R {
    try {
        return block(this)
    } finally {
        Encryption.RANDOM.nextBytes(this)
    }
}

internal fun Context.hasStrongBox(): Boolean {
    return SDK_INT >= P && packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
}

// Reconstruct key pair since Android Keystore stores public and private keys separately.
internal fun KeyStore.getKeyPair(alias: String): KeyPair? {
    return getCertificate(alias)?.let { certificate ->
        getKey(alias, null)?.let { key ->
            (key as? PrivateKey)?.let { KeyPair(certificate.publicKey, it) }
        }
    }
}

internal inline val <E> SparseArray<E>.lastKey get() = keyAt(size - 1)

internal fun <E> SparseArray<E>.reverseKeyIterator(): IntIterator {
    return object : IntIterator() {
        private var index = size - 1
        override fun hasNext() = index >= 0
        override fun nextInt() = keyAt(index--)
    }
}

internal fun String.decodeBase64() = Base64.decode(this, Base64.DEFAULT)
