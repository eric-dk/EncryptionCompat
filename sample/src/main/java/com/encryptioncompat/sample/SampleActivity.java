/*
 * Copyright © 2020 Eric Nguyen
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
import android.widget.TextView;
import com.google.android.material.snackbar.Snackbar;
import androidx.appcompat.app.AppCompatActivity;
import androidx.lifecycle.ViewModelProvider;

public class SampleActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_sample);

        TextView inputText = findViewById(R.id.inputText);
        TextView cipherText = findViewById(R.id.cipherText);
        TextView plainText = findViewById(R.id.plainText);

        ViewModelProvider.Factory factory =
                new ViewModelProvider.AndroidViewModelFactory(getApplication());
        SampleViewModel viewModel =
                new ViewModelProvider(this, factory).get(SampleViewModel.class);

        viewModel.getCipherText().observe(this, cipherText::setText);
        viewModel.getPlainText().observe(this, plainText::setText);
        viewModel.getErrorText().observe(this, text ->
                Snackbar.make(inputText, text, Snackbar.LENGTH_LONG).show()
        );

        findViewById(R.id.inputButton).setOnClickListener(view ->
                viewModel.setInputText(inputText.getText().toString())
        );
    }

    @Override
    public void onBackPressed() {
        moveTaskToBack(false);
    }
}
