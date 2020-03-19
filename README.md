# EncryptionCompat

String encryption on Android simplified. Intelligent key handling and automatic cipher management providing confidentiality, integrity, and authenticity. Supports down to API level 14 and fully backwards compatible when upgrading OS. Uses authenticated AES as cryptographic primitive.

[![](https://jitpack.io/v/com.github.eric-dk/EncryptionCompat.svg)](https://jitpack.io/#com.github.eric-dk/EncryptionCompat) [![](https://jitci.com/gh/eric-dk/EncryptionCompat/svg)](https://jitci.com/gh/eric-dk/EncryptionCompat)

**Important Note**: Moving to 4.x.x or 3.x.x from an older version requires a migration.

## Features

* **Flexible**: Use your preferred async handling via callback, Kotlin coroutines, or RxJava
* **Lightweight**: No massive dependencies; built on standard Java and Android crypto libraries
* **No-nonce-sense**: Really easy to integrate, really hard to mis-configure

## Quick Start

Add one of the following to your dependencies ([requires JitPack](https://jitpack.io/#com.github.eric-dk/EncryptionCompat/howto)) 
```groovy
implementation 'com.github.eric-dk.EncryptionCompat:core:4.0.0'
// Or with RxJava extensions
implementation 'com.github.eric-dk.EncryptionCompat:rx:4.0.0'
```

A very minimal example
```kotlin
val encryption = EncryptionCompat(context, minSdk)
CoroutineScope(Dispatchers.IO).launch {
    val ciphertext = encryption.encrypt("foo")
    val plaintext = encryption.decrypt(ciphertext)
}
```

## Modes

Preferred key mode depends on platform version and successful key generation - may fallback to a legacy mode. Preferred cipher mode solely depends on platform version. Legacy key and cipher modes depend on `minSdk`; for compatibility purposes, you may specify `0` to load all legacy modes. Each message contains the key and cipher mode used in encryption, thus preserving backwards-compatibility for decryption.

### Key Modes

* **Below API level 18**: Per-message AES key created from global password in [Shared Preferences](https://developer.android.com/training/data-storage/shared-preferences)
* **API level 18 - 23**: Per-instance AES key wrapped with global RSA key in [Android Keystore](https://developer.android.com/training/articles/keystore.html)
* **API level 23+**: Global AES key in Android Keystore
* **API level 28+**: Global AES key in [StrongBox Keymaster](https://developer.android.com/training/articles/keystore#HardwareSecurityModule); only [some devices](https://github.com/GrapheneOS/AttestationSamples)

### Cipher Modes

* **Below API level 21**: AES128-CBC with [Encrypt-then-Mac](https://en.wikipedia.org/wiki/Authenticated_encryption#Encrypt-then-MAC_(EtM))
* **API level 21+**: AES128-GCM

## Considerations

### Entropy
Randomization is provided by the manufacturer directly through [SecureRandom](https://developer.android.com/reference/java/security/SecureRandom) and indirectly through [Cipher](https://developer.android.com/reference/javax/crypto/Cipher). There have been real-world examples with [weak](https://android-developers.googleblog.com/2013/08/some-securerandom-thoughts.html) or simply [zero-filled](https://stackoverflow.com/a/31037133) values in the past. More modern devices should not exhibit any of these issues.

### Reliability
My experience with the keystore has varied by model, including from the same manufacturer. For example: a company-which-will-remain-unnamed's Nougat device refuses to save anything into keystore, whereas their Lollipop one has no problems. Hence why the key mode must be able to fallback. Changing the screen lock may also [invalidate](https://doridori.github.io/android-security-the-forgetful-keystore/) the keystore despite disabling user authentication. Even Google has had a [firmware bug](https://alexbakker.me/post/mysterious-google-titan-m-bug-cve-2019-9465.html) in their StrongBox Keymaster implementation on Pixel devices.

## Changelog

* **4.0.0**
    * Adds authenticated AES support
* **3.0.0**
    * Supports coroutines and RxJava
* **2.0.2**
    * Only throws EncryptionException
* **2.0.1**
    * Restricts visibility of internal classes
* **2.0.0**
    * Switches to non-static usage
* **1.0.2**
    * Improves sample behavior
* **1.0.1**
    * Adds library annotations
* **1.0.0**
    * Initial release

## Further Reading

[Security Best Practices: Symmetric Encryption with AES in Java and Android](https://proandroiddev.com/security-best-practices-symmetric-encryption-with-aes-in-java-7616beaaade9) by Patrick Favre-Bulle

[Secure data in Android — Encryption](https://proandroiddev.com/secure-data-in-android-encryption-7eda33e68f58) by Yakiv Mospan

[Using Password-based Encryption on Android](https://nelenkov.blogspot.com/2012/04/using-password-based-encryption-on.html) by Nikolay Elenkov

## License

    Copyright © 2020 Eric Nguyen

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
