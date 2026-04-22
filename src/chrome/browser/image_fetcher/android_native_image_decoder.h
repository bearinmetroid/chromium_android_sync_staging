// Copyright 2025 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef CHROME_BROWSER_IMAGE_FETCHER_ANDROID_NATIVE_IMAGE_DECODER_H_
#define CHROME_BROWSER_IMAGE_FETCHER_ANDROID_NATIVE_IMAGE_DECODER_H_

#include <string>

#include "components/image_fetcher/core/image_decoder.h"
#include "ui/gfx/geometry/size.h"
#include "ui/gfx/image/image.h"

// Android-native image decoder that uses BitmapFactory via JNI.
// This avoids the sandboxed Blink decoder which crashes on microG builds
// due to V8 snapshot loading failures in isolated processes.
class AndroidNativeImageDecoder : public image_fetcher::ImageDecoder {
 public:
  AndroidNativeImageDecoder();
  ~AndroidNativeImageDecoder() override;

  // ImageDecoder implementation
  void DecodeImage(const std::string& image_data,
                   const gfx::Size& desired_image_frame_size,
                   data_decoder::DataDecoder* data_decoder,
                   image_fetcher::ImageDecodedCallback callback) override;
};

#endif  // CHROME_BROWSER_IMAGE_FETCHER_ANDROID_NATIVE_IMAGE_DECODER_H_
