package com.encryptioncompat;

import android.content.Context;
import android.support.test.InstrumentationRegistry;
import android.support.test.filters.MediumTest;
import android.support.test.filters.SdkSuppress;
import android.support.test.runner.AndroidJUnit4;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import static android.os.Build.VERSION_CODES.JELLY_BEAN_MR1;
import static android.os.Build.VERSION_CODES.JELLY_BEAN_MR2;
import static android.os.Build.VERSION_CODES.LOLLIPOP_MR1;
import static android.os.Build.VERSION_CODES.M;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

@RunWith(AndroidJUnit4.class)
@MediumTest
public class EncryptionTest {
    private Context context;

    @Before
    public void setup() {
        context = InstrumentationRegistry.getTargetContext();
    }

    @Test
    public void testEncrypt_empty() {
        // Given
        String data = "";
        // When
        String actual = EncryptionCompat.encrypt(data, context);
        // Then
        assertThat(actual, is(data));
    }

    @Test
    public void testDecrypt_empty() {
        // Given
        String data = "";
        // When
        String actual = EncryptionCompat.decrypt(data, context);
        // Then
        assertThat(actual, is(data));
    }

    @SdkSuppress(maxSdkVersion = JELLY_BEAN_MR1)
    @Test
    public void testEncrypt_impl14Flag() {
        // Given
        String data = "abc";
        // When
        String encoded = EncryptionCompat.encrypt(data, context);
        String flag = encoded.substring(0, 1);
        // Then
        assertThat(flag, is(EncryptionCompat.SHARED_PREFS));
    }

    @SdkSuppress(maxSdkVersion = LOLLIPOP_MR1, minSdkVersion = JELLY_BEAN_MR2)
    @Test
    public void testEncrypt_impl18Flag() {
        // Given
        String data = "abc";
        // When
        String encoded = EncryptionCompat.encrypt(data, context);
        String flag = encoded.substring(0, 1);
        // Then
        assertThat(flag, is(EncryptionCompat.RSA_KEYSTORE));
    }

    @SdkSuppress(minSdkVersion = M)
    @Test
    public void testEncrypt_impl23Flag() {
        // Given
        String data = "abc";
        // When
        String encoded = EncryptionCompat.encrypt(data, context);
        String flag = encoded.substring(0, 1);
        // Then
        assertThat(flag, is(EncryptionCompat.AES_KEYSTORE));
    }

    @SdkSuppress(maxSdkVersion = JELLY_BEAN_MR1)
    @Test(expected = EncryptionException.class)
    public void testDecrypt_impl14Invalid() {
        // Given
        String data = EncryptionCompat.RSA_KEYSTORE;
        // When
        EncryptionCompat.decrypt(data, context);
        // Then
    }

    @SdkSuppress(maxSdkVersion = LOLLIPOP_MR1)
    @Test(expected = EncryptionException.class)
    public void testDecrypt_impl18Invalid() {
        // Given
        String data = EncryptionCompat.AES_KEYSTORE;
        // When
        EncryptionCompat.decrypt(data, context);
        // Then
    }

    @Test
    public void testEncryptDecrypt_impl14() {
        // Given
        String data = "abc";
        // When
        String encoded = EncryptionApi14Impl.get(context).encrypt(data);
        String decoded = EncryptionApi14Impl.get(context).decrypt(encoded);
        // Then
        assertThat(decoded, is(data));
    }

    @SdkSuppress(minSdkVersion = JELLY_BEAN_MR2)
    @Test
    public void testEncryptDecrypt_impl18() {
        // Given
        String data = "abc";
        // When
        String encoded = EncryptionApi18Impl.get(context).encrypt(data);
        String decoded = EncryptionApi18Impl.get(context).decrypt(encoded);
        // Then
        assertThat(decoded, is(data));
    }

    @SdkSuppress(minSdkVersion = M)
    @Test
    public void testEncryptDecrypt_impl23() {
        // Given
        String data = "abc";
        // When
        String encoded = EncryptionApi23Impl.get().encrypt(data);
        String decoded = EncryptionApi23Impl.get().decrypt(encoded);
        // Then
        assertThat(decoded, is(data));
    }
}
