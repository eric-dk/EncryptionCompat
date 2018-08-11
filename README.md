# EncryptionCompat

[![](https://jitpack.io/v/eric-dk/EncryptionCompat.svg)](https://jitpack.io/#eric-dk/EncryptionCompat)

Android encryption simplified. Automatic key management, preferring secure hardware. Backwards-compatible across platform versions. Best for obfuscating sensitive on-device data.

**Please carefully consider your threat model**. Encryption alone is not a security solution. Keys, even if hardware-backed, can [be extracted](https://developer.android.com/training/articles/keystore.html#ExtractionPrevention). Any data that touches a client should be considered compromisable.

Keys are *AES-256*, *CBC*, *PKCS7-padded*, but key management depends on the specified platform version.

* **Jelly Bean and below**: Per-message key is generated from a password stored in [shared preferences](https://developer.android.com/training/data-storage/shared-preferences) and a random salt. Salt, initialization vector, and ciphertext are then encoded.

* **KitKat through Lollipop**: Per-instance key is wrapped with a global RSA key saved to [the keystore](https://developer.android.com/training/articles/keystore.html). Keystore may be hardware-backed. Wrapped key, initialization vector, and ciphertext are then encoded.

* **Marshmallow and above**: Global key is managed by the keystore. Keystore may be hardware-backed. Initialization vector and ciphertext are then encoded.

## Usage

#### Initialization
```java
EncryptionCompat encryption = EncryptionCompat.newInstance();
```
For backwards-compatibility below Marshmallow:
```java
EncryptionCompat encryption = EncryptionCompat.newInstance(minSdk, context);
```

#### Data handling
```java
String encoded = encryption.encrypt("foobar");
String decoded = encryption.decrypt(encoded);
```

Encryption and decryption are blocking, and should be executed on non-UI thread(s). Checked exceptions are rethrown as unchecked EncyptionExceptions.

## Gradle

#### Add dependency to build.gradle
```gradle
repositories {
    maven { url 'https://jitpack.io' }
}

implementation 'com.github.eric-dk:EncryptionCompat:2.0.1'
```

## FAQ

#### Is there integrity protection?
No. EncryptionCompat provides data confidentiality only. Integrity checks should be implemented downstream.

#### Are random values securely generated?
Generally yes. Salt [randomization](https://developer.android.com/reference/java/security/SecureRandom.html) may have weak entropy depending [on manufacturer](https://android-developers.googleblog.com/2013/08/some-securerandom-thoughts.html). Initialization vector may be [zero-filled](https://stackoverflow.com/a/31037133) if [the cipher](https://developer.android.com/reference/javax/crypto/Cipher.html) is similarly poorly implemented.

#### Will upgrading OS invalidate data?
No. Decryption should reuse previous keys assuming no loss [due to hardware](https://doridori.github.io/android-security-the-forgetful-keystore/). When crossing implementation boundaries subsequent encryption will generate new, more secure keys.

## Changelog

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

## References

Credit to Yakiv Mospan for an excellent [series of articles](https://proandroiddev.com/secure-data-in-android-encryption-7eda33e68f58) on encryption using the keystore.  
Credit to Nikolay Elenkov for a [great post](https://nelenkov.blogspot.com/2012/04/using-password-based-encryption-on.html) on Android password-based encryption.

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
