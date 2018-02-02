# EncryptionCompat

[![](https://jitpack.io/v/eric-dk/EncryptionCompat.svg)](https://jitpack.io/#eric-dk/EncryptionCompat)

Android encryption simplified. Automatic key management, preferring secure hardware. Compatible across platform versions. Best for obfuscating sensitive data that for one reason or another exists on-device.

**Please carefully consider your threat model before using EncryptionCompat**. Encryption alone is not a security solution. Keys, even when hardware-backed, can be [used maliciously](https://developer.android.com/training/articles/keystore.html#ExtractionPrevention). Assume that anything that touches a device can and will be compromised.

Generally uses *AES-256*, *CBC*, *PKCS7-padded* keys, but key management differs depending on Android version.

* **Jelly Bean and below**: A per-input AES key is derived from a generated password, stored in shared preferences, and a random salt. The salt, [initialization vector](https://en.wikipedia.org/wiki/Initialization_vector), and ciphertext are encoded into the result.

* **KitKat through Lollipop**: A global AES key is wrapped with a RSA key, which is managed by the [Android Keystore](https://developer.android.com/training/articles/keystore.html) and may be hardware-backed. The wrapped key, initialization vector, and ciphertext are encoded into the result.

* **Marshmallow and above**: A global AES key is managed by Android Keystore, which may be hardware-backed. The initialization vector and ciphertext are encoded into the result.

## Usage

```java
String encrypted = EncryptionCompat.encrypt("foobar", context);
String decrypted = EncryptionCompat.decrypt(encrypted, context);
```

Encrypt and decrypt are thread-safe blocking operations, thus should be called on background thread(s). Any checked exceptions are rethrown as unchecked EncyptionException. Context is required for initialization.

## Gradle

#### Add dependency to build.gradle
```gradle
repositories {
    maven { url 'https://jitpack.io' }
}

implementation 'com.github.eric-dk:EncryptionCompat:1.0.0'
```

## FAQ

#### Does it provide integrity protection?
EncryptionCompat provides encrpytion, which only protects data confidentiality. Any data integrity checks should be implemented downstream.

#### Are random values securely generated?
Salts are randomized by [SecureRandom](https://developer.android.com/reference/java/security/SecureRandom.html), initialization vectors are populated by [Cipher](https://developer.android.com/reference/javax/crypto/Cipher.html); the former may have [weak entropy](https://android-developers.googleblog.com/2013/08/some-securerandom-thoughts.html), the latter may be [zero-byte filled](https://stackoverflow.com/a/31037133). These can be avoided by targeting newer versions of Android.

#### What if the user updates Android version?
Decryption should reuse previous keys, although the Android Keystore can [forget them](https://doridori.github.io/android-security-the-forgetful-keystore/). Subsequent encryptions will create new keys if crossing implementations above.

#### Why is the minimum SDK version set to API level 14?
The Android Support library only supports API level 14 and above. Also consider the security implications of running Gingerbread in 2018.

## Changelog

* **1.0.0**
    * Initial release

## References

Credit to Yakiv Mospan for an excellent [series of articles](https://proandroiddev.com/secure-data-in-android-encryption-7eda33e68f58) on encryption using Android Keystore. Note that it is currently incomplete as of early 2018. Thanks also to Nikolay Elenkov a [great post](https://nelenkov.blogspot.com/2012/04/using-password-based-encryption-on.html) on password-based encryption on Android.

## License

    Copyright © 2018 Eric Nguyen

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
