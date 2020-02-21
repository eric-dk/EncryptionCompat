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
import android.os.Build
import android.util.Base64
import android.util.SparseArray
import androidx.core.util.size

internal fun ByteArray.encode() = Base64.encodeToString(this, Base64.DEFAULT)

internal inline val Context.appName get() = "${applicationInfo.loadLabel(packageManager)}"

internal fun PackageManager.hasStrongBox(): Boolean {
    return Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
           hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
}

internal fun <E> SparseArray<E>.reverseKeyIterator(): IntIterator {
    return object : IntIterator() {
        private var index = size - 1
        override fun hasNext() = index >= 0
        override fun nextInt() = keyAt(index--)
    }
}

internal fun String.decode() = Base64.decode(this, Base64.DEFAULT)
