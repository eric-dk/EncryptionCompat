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

import android.os.Bundle;
import androidx.appcompat.app.AppCompatActivity;
import androidx.lifecycle.ViewModelProvider;
import com.encryptioncompat.sample.databinding.ActivitySampleBinding;
import com.google.android.material.snackbar.Snackbar;

public class SampleActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        ActivitySampleBinding binding = ActivitySampleBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        ViewModelProvider.Factory factory =
                new ViewModelProvider.AndroidViewModelFactory(getApplication());
        SampleViewModel viewModel =
                new ViewModelProvider(getViewModelStore(), factory).get(SampleViewModel.class);

        viewModel.getCipherText().observe(this, binding.cipherText::setText);
        viewModel.getPlainText().observe(this, binding.plainText::setText);
        viewModel.getErrorText().observe(this, text ->
                Snackbar.make(binding.inputText, text, Snackbar.LENGTH_LONG).show()
        );

        findViewById(R.id.inputButton).setOnClickListener(view ->
                viewModel.setInputText(binding.inputText.getText().toString())
        );
    }
}
