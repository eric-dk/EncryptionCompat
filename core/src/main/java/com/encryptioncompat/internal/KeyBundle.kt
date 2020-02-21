package com.encryptioncompat.internal

import java.security.Key

internal data class KeyBundle(val key: Key, val metadata: String?)
