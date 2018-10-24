/*
 * Copyright © 2018 Eric Nguyen
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

package com.encryptioncompat;

import android.content.Context;
import androidx.test.core.app.ApplicationProvider;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import androidx.test.filters.MediumTest;
import androidx.test.filters.SdkSuppress;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import static android.os.Build.VERSION_CODES.ICE_CREAM_SANDWICH;
import static android.os.Build.VERSION_CODES.JELLY_BEAN_MR1;
import static android.os.Build.VERSION_CODES.JELLY_BEAN_MR2;
import static android.os.Build.VERSION_CODES.LOLLIPOP_MR1;
import static android.os.Build.VERSION_CODES.M;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

@RunWith(AndroidJUnit4.class)
@MediumTest
public class EncryptionTest {
    private EncryptionCompat encryption;

    @Before
    public void setup() {
        Context context = ApplicationProvider.getApplicationContext();
        encryption = EncryptionCompat.newInstance(ICE_CREAM_SANDWICH, context);
    }

    @Test
    public void testEncrypt_empty() {
        // Given
        String input = "";
        // When
        String actual = encryption.encrypt(input);
        // Then
        assertThat(actual, is(input));
    }

    @Test
    public void testDecrypt_empty() {
        // Given
        String input = "";
        // When
        String actual = encryption.decrypt(input);
        // Then
        assertThat(actual, is(input));
    }

    @SdkSuppress(maxSdkVersion = JELLY_BEAN_MR1)
    @Test
    public void testEncrypt_api14Mode() {
        // Given
        String input = "abc";
        // When
        String encoded = encryption.encrypt(input);
        String flag = encoded.substring(0, 1);
        // Then
        assertThat(flag, is(EncryptionCompat.SHARED_PREFS));
    }

    @SdkSuppress(minSdkVersion = JELLY_BEAN_MR2, maxSdkVersion = LOLLIPOP_MR1)
    @Test
    public void testEncrypt_api18Mode() {
        // Given
        String input = "abc";
        // When
        String encoded = encryption.encrypt(input);
        String flag = encoded.substring(0, 1);
        // Then
        assertThat(flag, is(EncryptionCompat.RSA_KEYSTORE));
    }

    @SdkSuppress(minSdkVersion = M)
    @Test
    public void testEncrypt_api23Mode() {
        // Given
        String input = "abc";
        // When
        String encoded = encryption.encrypt(input);
        String flag = encoded.substring(0, 1);
        // Then
        assertThat(flag, is(EncryptionCompat.AES_KEYSTORE));
    }

    @SdkSuppress(maxSdkVersion = JELLY_BEAN_MR1)
    @Test(expected = EncryptionException.class)
    public void testDecrypt_api14BadMode() {
        // Given
        String input = EncryptionCompat.RSA_KEYSTORE;
        // When
        encryption.decrypt(input);
        // Then
    }

    @SdkSuppress(maxSdkVersion = LOLLIPOP_MR1)
    @Test(expected = EncryptionException.class)
    public void testDecrypt_api18BadMode() {
        // Given
        String input = EncryptionCompat.AES_KEYSTORE;
        // When
        encryption.decrypt(input);
        // Then
    }

    @Test
    public void testEncrypt_decrypt() {
        // Given
        String input = "abc";
        // When
        String encoded = encryption.encrypt(input);
        String decoded = encryption.decrypt(encoded);
        // Then
        assertThat(decoded, is(input));
    }
}
