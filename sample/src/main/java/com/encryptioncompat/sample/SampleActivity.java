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
import android.util.Log;
import android.view.View;
import android.widget.TextView;
import androidx.appcompat.app.AppCompatActivity;
import com.encryptioncompat.EncryptionCompat;
import com.encryptioncompat.EncryptionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import static android.os.Build.VERSION_CODES.ICE_CREAM_SANDWICH;

public class SampleActivity extends AppCompatActivity {
    private EncryptionCompat encryption;
    private ExecutorService executor;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_sample);

        encryption = EncryptionCompat.newInstance(ICE_CREAM_SANDWICH, this);
        executor = Executors.newSingleThreadExecutor();

        final TextView inputText = findViewById(R.id.inputText);
        final TextView cipherText = findViewById(R.id.cipherText);
        final TextView plainText = findViewById(R.id.plainText);

        findViewById(R.id.inputButton).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                final String input = inputText.getText().toString();
                executor.submit(new Runnable() {
                    @Override
                    public void run() {
                        try {
                            final String encoded = encryption.encrypt(input).trim();
                            final String decoded = encryption.decrypt(encoded).trim();

                            runOnUiThread(new Runnable() {
                                @Override
                                public void run() {
                                    if (!isFinishing()) {
                                        cipherText.setText(encoded);
                                        plainText.setText(decoded);
                                    }
                                }
                            });
                        } catch (EncryptionException e) {
                            Log.e(getString(R.string.name), e.toString(), e);
                        }
                    }
                });
            }
        });
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executor.shutdown();
    }

    @Override
    public void onBackPressed() {
        startActivity(new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME));
    }
}
