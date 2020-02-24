# EncryptionCompat

[![](https://jitpack.io/v/com.github.eric-dk/EncryptionCompat.svg)](https://jitpack.io/#com.github.eric-dk/EncryptionCompat)

Android encryption simplified. Automatic key management, preferring secure hardware. Backwards compatible across platform versions. Best for obfuscating sensitive data.

**Carefully consider your threat model**. Encryption alone is not security; keys can be extracted given [enough means](https://developer.android.com/training/articles/keystore.html#ExtractionPrevention). All data that touches a client should be considered compromisable.

Messages are encrypted with a *AES256/CBC/PKCS7* key, but the key management scheme depends on device support.

* **Least secure (below API 18)**: A per-message key is created from a random salt and a global password - stored in [shared preferences](https://developer.android.com/training/data-storage/shared-preferences). The initialization vector, ciphertext, and salt are then encoded.

* **More secure (API 18-22)**: A per-instance key is wrapped with a global asymmetric key - saved in the [Android Keystore](https://developer.android.com/training/articles/keystore.html). The initialization vector, ciphertext, and wrapped key are then encoded.

* **Most secure (API 23+)**: A global key is managed by the Android Keystore, which may be bound to a trusted execution environment. The initialization vector and ciphertext are then encoded.

* **Most secure (API 28+)**: Same as above, but the key is stored in a [hardware security module](https://developer.android.com/training/articles/keystore#HardwareSecurityModule); only available on a [few devices](https://github.com/GrapheneOS/AttestationSamples). The initialization vector and ciphertext are then encoded.

Due to manufacturer fragmentation, EncryptionCompat will attempt the highest possible scheme then fall through until reaching the specified minimum platform.

## Usage

#### Initialization

EncryptionCompat requires `Context` and a minimum platform, which should be equal to `minSdkVersion`. However, going lower increases compatibility with troublesome devices (see sample).

**Kotlin**
```kotlin
val encryption = EncryptionCompat(context, minSdk)
```
**Java**
```java
EncryptionCompat encryption = new EncryptionCompat(context, minSdk);
```

A version with [RxJava 2.x](https://github.com/ReactiveX/RxJava) bindings is also available.

**Kotlin**
```kotlin
val encryption = RxEncryptionCompat(context, minSdk)
```
**Java**
```java
RxEncryptionCompat encryption = new RxEncryptionCompat(context, minSdk);
```

#### Message handling

EncryptionCompat runs on an independent single thread to ensure sequential key access. You can retrieve output by providing a callback, handling the suspending function, or observing the [RxJava Single](http://reactivex.io/documentation/single.html). Please note that 3.x.x is not backwards compatible and cannot read previously encrypted messages.

## Gradle

#### Adding dependency

Add the maven repository to the project `build.gradle`:
```gradle
allprojects {
    repositories {
        maven { url 'https://jitpack.io' }
    }
}
```

Add the dependency to the module `build.gradle`:
```gradle
// If using callbacks or coroutines
implementation 'com.github.eric-dk.EncryptionCompat:core:3.0.0'
// If using RxJava only
implementation 'com.github.eric-dk.EncryptionCompat:rx:3.0.0'
```

## FAQ

#### Is integrity protection provided?
No. EncryptionCompat provides confidentiality only. Performing integrity checks downstream is recommended.

#### Are random values securely generated?
Probably. Randomization may have weak entropy depending on [manufacturer](https://android-developers.googleblog.com/2013/08/some-securerandom-thoughts.html). The initialization vector may also be [zero-filled](https://stackoverflow.com/a/31037133).

#### Will upgrading Android invalidate data?
No. Decryption should reuse previous keys [assuming no loss](https://doridori.github.io/android-security-the-forgetful-keystore/). Subsequent messages will be encrypted with new, more secure keys.

## Changelog

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

## References

Credit goes to Yakiv Mospan for an excellent [series of articles](https://proandroiddev.com/secure-data-in-android-encryption-7eda33e68f58) on using the Android Keystore.  
Credit goes to Nikolay Elenkov for a [great post](https://nelenkov.blogspot.com/2012/04/using-password-based-encryption-on.html) regarding password-based encryption on Android.

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
