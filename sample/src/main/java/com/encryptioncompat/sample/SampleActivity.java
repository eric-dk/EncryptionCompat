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
    @BindView(R.id.inputText) TextView inputText;
    @BindView(R.id.cipherText) TextView cipherText;
    @BindView(R.id.plainText) TextView plainText;

    private final HandlerThread workerThread = new HandlerThread("Worker");
    private Handler mainHandler;
    private Handler workerHandler;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_sample);
        ButterKnife.bind(this);

        workerThread.start();
        mainHandler = new Handler(Looper.getMainLooper()) {
            @Override
            public void handleMessage(Message msg) {
                // noinspection unchecked
                Pair<String, String> output = (Pair<String, String>)msg.obj;
                cipherText.setText(output.first.trim());
                plainText.setText(output.second.trim());
            }
        };
        workerHandler = new Handler(workerThread.getLooper()) {
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
                mainHandler.obtainMessage(0, output).sendToTarget();
            }
        };
    }

    @Override
    protected void onDestroy() {
        workerThread.quit();
        super.onDestroy();
    }

    @OnClick(R.id.inputButton)
    void doEncrypt() {
        String input = inputText.getText().toString();
        workerHandler.obtainMessage(0, input).sendToTarget();
    }
}
