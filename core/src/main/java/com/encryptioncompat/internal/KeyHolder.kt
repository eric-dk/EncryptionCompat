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

import java.security.Key

internal interface KeyHolder {
    companion object {
        const val AES = "AES"
        const val LENGTH = 256
        const val PROVIDER = "AndroidKeyStore"
    }

    fun getEncryptBundle(): KeyBundle
    fun getDecryptKey(metadata: ByteArray): Key
}
