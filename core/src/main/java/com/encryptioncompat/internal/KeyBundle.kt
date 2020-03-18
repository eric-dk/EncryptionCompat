package com.encryptioncompat.internal

import java.security.Key

/**
 * Key material and any supplemental data to be added to the message.
 *
 * @param key           AES key
 * @param supplement    (Optional) Supplemental data
 */
internal class KeyBundle(val key: Key, val supplement: ByteArray = ByteArray(0))
