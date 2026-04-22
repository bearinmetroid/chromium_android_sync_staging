// Copyright 2025 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.components.image_fetcher;

import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.util.Log;

import org.jni_zero.CalledByNative;
import org.jni_zero.JNINamespace;

/**
 * Android-native image decoder using BitmapFactory.
 * Called from C++ via JNI to decode profile images without sandboxed processes.
 */
@JNINamespace("image_fetcher")
public class NativeImageDecoder {
    private static final String TAG = "cr_NativeImageDecoder";

    @CalledByNative
    public static Bitmap decode(byte[] imageData) {
        if (imageData == null || imageData.length == 0) {
            Log.e(TAG, "✗ Empty image data");
            return null;
        }

        Bitmap bitmap = BitmapFactory.decodeByteArray(imageData, 0, imageData.length);

        if (bitmap == null) {
            Log.e(TAG, "✗ Failed to decode image");
            return null;
        }

        Log.i(TAG, "✓ Successfully decoded image: " + bitmap.getWidth() + "x"
                + bitmap.getHeight() + ", config=" + bitmap.getConfig());
        return bitmap;
    }
}
