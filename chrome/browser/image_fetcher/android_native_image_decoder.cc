// Copyright 2025 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "chrome/browser/image_fetcher/android_native_image_decoder.h"

#include "base/android/jni_android.h"
#include "base/android/jni_array.h"
#include "base/functional/bind.h"
#include "base/task/thread_pool.h"
#include "components/image_fetcher/jni_headers/NativeImageDecoder_jni.h"
#include "ui/gfx/android/java_bitmap.h"

using base::android::AttachCurrentThread;
using base::android::ScopedJavaLocalRef;

AndroidNativeImageDecoder::AndroidNativeImageDecoder() = default;
AndroidNativeImageDecoder::~AndroidNativeImageDecoder() = default;

void AndroidNativeImageDecoder::DecodeImage(
    const std::string& image_data,
    const gfx::Size& desired_image_frame_size,
    data_decoder::DataDecoder* data_decoder,
    image_fetcher::ImageDecodedCallback callback) {

  // Decode on background thread to avoid blocking UI
  base::ThreadPool::PostTaskAndReplyWithResult(
      FROM_HERE, {base::MayBlock(), base::TaskPriority::USER_VISIBLE},
      base::BindOnce(
          [](const std::string& data) -> gfx::Image {
            JNIEnv* env = AttachCurrentThread();

            // Convert C++ byte array to Java byte[]
            ScopedJavaLocalRef<jbyteArray> j_image_data =
                base::android::ToJavaByteArray(
                    env, reinterpret_cast<const uint8_t*>(data.data()),
                    data.size());

            // Call Java decoder (namespace-qualified)
            ScopedJavaLocalRef<jobject> j_bitmap =
                image_fetcher::Java_NativeImageDecoder_decode(env, j_image_data);

            if (j_bitmap.is_null()) {
              return gfx::Image();
            }

            // Convert Java Bitmap to SkBitmap
            gfx::JavaBitmap java_bitmap(j_bitmap);
            SkBitmap sk_bitmap = gfx::CreateSkBitmapFromJavaBitmap(java_bitmap);

            return gfx::Image::CreateFrom1xBitmap(sk_bitmap);
          },
          image_data),
      std::move(callback));
}
