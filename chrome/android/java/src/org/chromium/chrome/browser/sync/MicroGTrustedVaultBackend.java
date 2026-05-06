// Copyright 2025 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.chrome.browser.sync;

import android.app.PendingIntent;

import org.chromium.base.Promise;
import org.chromium.build.annotations.NullMarked;
import org.chromium.build.annotations.ServiceImpl;
import org.chromium.components.signin.base.CoreAccountInfo;

import java.util.Collections;
import java.util.List;

/**
 * microG-compatible implementation of {@link TrustedVaultClient.Backend}.
 *
 * Suppresses encryption key retrieval errors by returning empty/fulfilled promises
 * instead of rejections. Sync continues to work without client-side encryption.
 *
 * Discovered via ServiceLoader — the @ServiceImpl annotation generates META-INF/services
 * entries so TrustedVaultClient uses this instead of EmptyBackend.
 */
@ServiceImpl(TrustedVaultClient.Backend.class)
@NullMarked
public class MicroGTrustedVaultBackend implements TrustedVaultClient.Backend {

    @Override
    public Promise<List<byte[]>> fetchKeys(CoreAccountInfo accountInfo) {
        return Promise.fulfilled(Collections.emptyList());
    }

    @Override
    public Promise<PendingIntent> createKeyRetrievalIntent(CoreAccountInfo accountInfo) {
        return Promise.fulfilled(null);
    }

    @Override
    public Promise<Boolean> markLocalKeysAsStale(CoreAccountInfo accountInfo) {
        return Promise.fulfilled(false);
    }

    @Override
    public Promise<Boolean> getIsRecoverabilityDegraded(CoreAccountInfo accountInfo) {
        return Promise.fulfilled(false);
    }

    @Override
    public Promise<Void> addTrustedRecoveryMethod(
            CoreAccountInfo accountInfo, byte[] publicKey, int methodTypeHint) {
        return Promise.rejected();
    }

    @Override
    public Promise<PendingIntent> createRecoverabilityDegradedIntent(CoreAccountInfo accountInfo) {
        return Promise.fulfilled(null);
    }

    @Override
    public Promise<PendingIntent> createOptInIntent(CoreAccountInfo accountInfo) {
        return Promise.fulfilled(null);
    }
}
