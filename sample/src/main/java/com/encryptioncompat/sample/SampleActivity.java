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

package com.encryptioncompat.sample;

import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Looper;
import android.os.Message;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import android.util.Pair;
import android.widget.TextView;
import com.encryptioncompat.EncryptionCompat;
import com.encryptioncompat.EncryptionException;
import butterknife.BindView;
import butterknife.ButterKnife;
import butterknife.OnClick;

public class SampleActivity extends AppCompatActivity {
    @BindView(R.id.inputText) @SuppressWarnings("WeakerAccess") TextView inputText;
    @BindView(R.id.cipherText) @SuppressWarnings("WeakerAccess") TextView cipherText;
    @BindView(R.id.plainText) @SuppressWarnings("WeakerAccess") TextView plainText;

    private final HandlerThread bgThread = new HandlerThread("Background");
    private Handler bgHandler;
    private Handler uiHandler;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_sample);
        ButterKnife.bind(this);

        bgThread.start();
        bgHandler = new Handler(bgThread.getLooper()) {
            @Override
            public void handleMessage(Message msg) {
                String input = msg.obj.toString();
                String encoded, decoded;
                try {
                    encoded = EncryptionCompat.encrypt(input, SampleActivity.this);
                    decoded = EncryptionCompat.decrypt(encoded, SampleActivity.this);
                } catch (EncryptionException e) {
                    encoded = e.toString();
                    decoded = "";
                    Log.e(getString(R.string.name), encoded, e);
                }

                Pair<String, String> output = new Pair<>(encoded, decoded);
                uiHandler.obtainMessage(0, output).sendToTarget();
            }
        };
        uiHandler = new Handler(Looper.getMainLooper()) {
            @Override
            public void handleMessage(Message msg) {
                // noinspection unchecked
                Pair<String, String> output = (Pair<String, String>)msg.obj;
                cipherText.setText(output.first.trim());
                plainText.setText(output.second.trim());
            }
        };
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        bgThread.quit();
    }

    @OnClick(R.id.inputButton)
    void doEncrypt() {
        String input = inputText.getText().toString();
        bgHandler.obtainMessage(0, input).sendToTarget();
    }

    @Override
    public void onBackPressed() {
        startActivity(new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME));
    }
}
