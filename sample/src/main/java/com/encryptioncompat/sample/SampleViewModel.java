/*
 * Copyright © 2024 Eric Nguyen
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

package com.encryptioncompat.sample;

import android.app.Application;
import android.content.Context;
import android.content.SharedPreferences;
import android.os.Build;
import android.util.Log;
import com.encryptioncompat.EncryptionCompat;
import androidx.annotation.NonNull;
import androidx.lifecycle.AndroidViewModel;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

public class SampleViewModel extends AndroidViewModel {
    private static final String TEXT_KEY = "TEXT";

    private final EncryptionCompat.Callback encryptCallback = new EncryptionCompat.Callback() {
        @Override
        public void onSuccess(@NonNull String output) {
            cipherText.setValue(output);
            encryption.decrypt(decryptCallback, output);
            sharedPreferences.edit().putString(TEXT_KEY, output).apply();
        }
        @Override
        public void onFailure(@NonNull Throwable throwable) {
            Log.e(getApplication().getString(R.string.name), "Encrypt failure", throwable);
            errorText.setValue(throwable.getClass().getSimpleName());
        }
    };
    private final EncryptionCompat.Callback decryptCallback = new EncryptionCompat.Callback() {
        @Override
        public void onSuccess(@NonNull String output) {
            plainText.setValue(output);
        }
        @Override
        public void onFailure(@NonNull Throwable throwable) {
            Log.e(getApplication().getString(R.string.name), "Decrypt failure", throwable);
            errorText.setValue(throwable.getClass().getSimpleName());
        }
    };

    private final MutableLiveData<CharSequence> cipherText = new MutableLiveData<>();
    private final MutableLiveData<CharSequence> errorText = new MutableLiveData<>();
    private final MutableLiveData<CharSequence> plainText = new MutableLiveData<>();

    private final EncryptionCompat encryption;
    private final SharedPreferences sharedPreferences;

    public SampleViewModel(Application application) {
        super(application);
        encryption = new EncryptionCompat(application, Build.VERSION_CODES.BASE);
        sharedPreferences = application.getSharedPreferences("Sample", Context.MODE_PRIVATE);

        final String text = sharedPreferences.getString(TEXT_KEY, null);
        if (text != null) {
            cipherText.setValue(text);
            encryption.decrypt(decryptCallback, text);
        }
    }

    void setInputText(String input) {
        encryption.encrypt(encryptCallback, input);
    }

    LiveData<CharSequence> getCipherText() {
        return cipherText;
    }

    LiveData<CharSequence> getErrorText() {
        return errorText;
    }

    LiveData<CharSequence> getPlainText() {
        return plainText;
    }
}
