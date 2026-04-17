// Copyright 2025 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.components.signin;

import static org.chromium.build.NullUtil.assumeNonNull;

import android.accounts.Account;
import android.accounts.AccountManager;
import android.accounts.AccountManagerCallback;
import android.accounts.AccountManagerFuture;
import android.accounts.AuthenticatorException;
import android.accounts.OperationCanceledException;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.ContentResolver;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.IntentFilter;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Bundle;
import android.os.Parcelable;

import com.google.android.gms.auth.GoogleAuthException;
import com.google.android.gms.auth.GoogleAuthUtil;

import org.chromium.base.Callback;
import org.chromium.base.ContextUtils;
import org.chromium.base.Log;
import org.chromium.base.ThreadUtils;
import org.chromium.build.annotations.NullMarked;
import org.chromium.build.annotations.Nullable;
import org.chromium.build.annotations.ServiceImpl;
import org.chromium.google_apis.gaia.GaiaId;
import org.chromium.google_apis.gaia.GoogleServiceAuthError;
import org.chromium.google_apis.gaia.GoogleServiceAuthErrorState;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.json.JSONObject;

/**
 * microG-compatible implementation of {@link AccountManagerDelegate}.
 *
 * Supports two modes:
 * 1. ReVanced microG (app.revanced.android.gms) — uses account type "app.revanced".
 *    Works on devices with real Google Play Services installed alongside ReVanced microG.
 * 2. Upstream microG (com.google.android.gms replacement) — uses account type "com.google".
 *    Works on devices where microG fully replaces Google Play Services.
 *
 * On Android 8+, accounts from other authenticators are not visible via
 * AccountManager.getAccountsByType(). For ReVanced microG, this delegate falls
 * back to querying all accounts and filtering.
 *
 * Discovered via ServiceLoader — the @ServiceImpl annotation generates
 * META-INF/services entries so AccountManagerFacadeProvider uses this
 * instead of SystemAccountManagerDelegate.
 */
@ServiceImpl(AccountManagerDelegate.class)
@NullMarked
public class MicroGAccountManagerDelegate implements AccountManagerDelegate {
    private static final String TAG = "MicroGAccountDelegate";
    private static final String GOOGLE_ACCOUNT_TYPE = "com.google";
    private static final String REVANCED_ACCOUNT_TYPE = "app.revanced";
    private static final String REVANCED_GMS_PACKAGE = "app.revanced.android.gms";

    // GmsCore AccountContentProvider constants
    private static final String REVANCED_AUTH_AUTHORITY = "app.revanced.android.gms.auth.accounts";
    private static final String PROVIDER_METHOD_GET_ACCOUNTS = "get_accounts";
    private static final String PROVIDER_EXTRA_ACCOUNTS = "accounts";

    private final AccountManager mAccountManager;
    private final String mAccountType;
    private @Nullable AccountsChangeObserver mObserver;

    // Fix for random sign-out: Debounce account change broadcasts
    private static final long ACCOUNT_CHANGE_DEBOUNCE_MS = 2000;
    private long mLastAccountChangeTime = 0;

    // Fix for random sign-out: Suppress broadcasts during Gaia ID extraction
    // When extracting real Gaia ID from API, don't process broadcasts until done
    private static final long GAIA_EXTRACTION_GRACE_PERIOD_MS = 5000;
    private volatile long mGaiaExtractionStartTime = 0;
    private volatile boolean mGaiaExtractionInProgress = false;

    // Fix for random sign-out: Retry count for ContentProvider
    private static final int CONTENT_PROVIDER_MAX_RETRIES = 3;
    private static final long CONTENT_PROVIDER_RETRY_DELAY_MS = 100;

    // Fix for random sign-out: Persist Gaia IDs to prevent mismatch on app restart
    private static final String GAIA_ID_PREFS_NAME = "microg_gaia_ids";
    private static final String GAIA_ID_PREFIX = "gaia_id_";

    public MicroGAccountManagerDelegate() {
        mAccountManager = AccountManager.get(ContextUtils.getApplicationContext());
        mAccountType = detectAccountType();
        Log.i(TAG, "MicroGAccountManagerDelegate initialized, account type: %s", mAccountType);
    }

    private String detectAccountType() {
        try {
            ContextUtils.getApplicationContext()
                    .getPackageManager()
                    .getPackageInfo(REVANCED_GMS_PACKAGE, 0);
            Log.i(TAG, "ReVanced microG detected, using account type: %s", REVANCED_ACCOUNT_TYPE);
            return REVANCED_ACCOUNT_TYPE;
        } catch (PackageManager.NameNotFoundException e) {
            Log.i(TAG, "ReVanced microG not found, falling back to standard account type");
            return GOOGLE_ACCOUNT_TYPE;
        }
    }

    @Override
    public void attachAccountsChangeObserver(AccountsChangeObserver observer) {
        assert mObserver == null : "Another AccountsChangeObserver is already attached!";
        mObserver = observer;
        Context context = ContextUtils.getApplicationContext();
        BroadcastReceiver receiver =
                new BroadcastReceiver() {
                    @Override
                    public void onReceive(final Context context, final Intent intent) {
                        // Fix for random sign-out: Debounce rapid account change broadcasts
                        // ReVanced microG can emit multiple broadcasts during token refresh,
                        // service restart, or account operations. Without debouncing, each
                        // broadcast triggers account re-enumeration which may fail and cause sign-out.
                        long now = android.os.SystemClock.uptimeMillis();

                        // Fix for random sign-out: Don't process broadcasts during Gaia ID extraction
                        // When we're extracting the real Gaia ID from Google's API (after OAuthLogin
                        // token is obtained), processing broadcasts can cause Chrome to call
                        // getAccountGaiaId() before extraction completes, returning a fake ID
                        // that triggers sign-out.
                        if (mGaiaExtractionInProgress &&
                            (now - mGaiaExtractionStartTime < GAIA_EXTRACTION_GRACE_PERIOD_MS)) {
                            Log.i(TAG, "Ignoring account change broadcast (Gaia extraction in progress, %dms elapsed)",
                                    now - mGaiaExtractionStartTime);
                            return;
                        }

                        if (now - mLastAccountChangeTime < ACCOUNT_CHANGE_DEBOUNCE_MS) {
                            Log.d(TAG, "Ignoring account change broadcast (debounced, %dms since last)",
                                    now - mLastAccountChangeTime);
                            return;
                        }
                        mLastAccountChangeTime = now;
                        Log.i(TAG, "Processing account change broadcast");
                        assumeNonNull(mObserver).onCoreAccountInfosChanged();
                    }
                };
        IntentFilter accountsChangedIntentFilter = new IntentFilter();
        accountsChangedIntentFilter.addAction(AccountManager.LOGIN_ACCOUNTS_CHANGED_ACTION);
        ContextUtils.registerProtectedBroadcastReceiver(
                context, receiver, accountsChangedIntentFilter);
    }

    @Override
    public Account[] getAccountsSynchronous() throws AccountManagerDelegateException {
        // For ReVanced microG, we MUST call through the ContentProvider first.
        // This triggers GmsCore to grant account visibility to our app (Android 8+ requirement).
        // Without this, AccountManager.getAccountsByType() returns empty even if accounts exist.
        if (REVANCED_ACCOUNT_TYPE.equals(mAccountType)) {
            Account[] accounts = getAccountsViaContentProvider();
            if (accounts.length > 0) {
                Log.i(TAG, "ContentProvider returned %d accounts", accounts.length);
                return accounts;
            }
            // ContentProvider call might have set visibility - try AccountManager now
            Log.i(TAG, "ContentProvider returned 0 accounts, trying AccountManager");
        }

        // Try AccountManager directly (no permission gate — let it fail naturally)
        try {
            Account[] accounts = mAccountManager.getAccountsByType(mAccountType);
            Log.i(TAG, "AccountManager returned %d accounts of type '%s'",
                    accounts.length, mAccountType);
            if (accounts.length > 0) {
                return accounts;
            }
        } catch (SecurityException e) {
            Log.w(TAG, "AccountManager.getAccountsByType failed: ", e);
        }

        // Fallback for ReVanced microG: query all accounts and filter.
        // On Android 8+, AccountManager won't show accounts from other authenticators
        // unless visibility is explicitly granted.
        if (REVANCED_ACCOUNT_TYPE.equals(mAccountType)) {
            Log.i(TAG, "Trying fallback account enumeration for ReVanced microG");
            Account[] accounts = getAccountsAllFallback();
            if (accounts.length > 0) {
                return accounts;
            }
        }

        Log.w(TAG, "No accounts found via any method for type '%s'", mAccountType);
        return new Account[] {};
    }

    /**
     * Query accounts through GmsCore's AccountContentProvider.
     * This triggers the visibility grant mechanism that allows our app to see accounts.
     * On Android 8+, apps can only see accounts if visibility is explicitly granted.
     * GmsCore grants visibility when apps call through its ContentProvider.
     *
     * Fix for random sign-out: Added retry logic with exponential backoff.
     * The ContentProvider may fail or timeout when ReVanced microG service is
     * restarting or under load. Without retries, a single failure causes empty
     * account list → sign-out.
     */
    private Account[] getAccountsViaContentProvider() {
        ContentResolver resolver = ContextUtils.getApplicationContext().getContentResolver();
        Uri uri = Uri.parse("content://" + REVANCED_AUTH_AUTHORITY);

        for (int retry = 0; retry < CONTENT_PROVIDER_MAX_RETRIES; retry++) {
            try {
                // Call the ContentProvider's "get_accounts" method with account type as argument
                Bundle result = resolver.call(uri, PROVIDER_METHOD_GET_ACCOUNTS, mAccountType, null);
                if (result != null) {
                    Parcelable[] parcelables = result.getParcelableArray(PROVIDER_EXTRA_ACCOUNTS);
                    if (parcelables != null && parcelables.length > 0) {
                        Account[] accounts = new Account[parcelables.length];
                        for (int i = 0; i < parcelables.length; i++) {
                            accounts[i] = (Account) parcelables[i];
                        }
                        Log.i(TAG, "GmsCore ContentProvider returned %d accounts (attempt %d)",
                                accounts.length, retry + 1);
                        return accounts;
                    }
                }
                // Result was empty or null, might be transient - retry
                if (retry < CONTENT_PROVIDER_MAX_RETRIES - 1) {
                    Log.i(TAG, "ContentProvider returned empty, retrying (attempt %d/%d)",
                            retry + 1, CONTENT_PROVIDER_MAX_RETRIES);
                    try {
                        // Exponential backoff: 100ms, 200ms, 400ms
                        Thread.sleep(CONTENT_PROVIDER_RETRY_DELAY_MS * (1 << retry));
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            } catch (Exception e) {
                Log.w(TAG, "ContentProvider query failed (attempt %d/%d): %s",
                        retry + 1, CONTENT_PROVIDER_MAX_RETRIES, e.getMessage());
                if (retry < CONTENT_PROVIDER_MAX_RETRIES - 1) {
                    try {
                        Thread.sleep(CONTENT_PROVIDER_RETRY_DELAY_MS * (1 << retry));
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }
            }
        }
        Log.i(TAG, "GmsCore ContentProvider returned no accounts after %d attempts",
                CONTENT_PROVIDER_MAX_RETRIES);
        return new Account[] {};
    }

    /**
     * Fallback account enumeration: query all accounts and filter by type.
     * Used when getAccountsByType() returns empty due to visibility restrictions.
     */
    @SuppressLint("MissingPermission")
    private Account[] getAccountsAllFallback() {
        try {
            Account[] allAccounts = mAccountManager.getAccounts();
            int count = 0;
            for (Account a : allAccounts) {
                if (mAccountType.equals(a.type)) count++;
            }
            if (count > 0) {
                Account[] filtered = new Account[count];
                int idx = 0;
                for (Account a : allAccounts) {
                    if (mAccountType.equals(a.type)) {
                        filtered[idx++] = a;
                    }
                }
                Log.i(TAG, "Fallback found %d accounts of type '%s'", count, mAccountType);
                return filtered;
            }
        } catch (SecurityException e) {
            Log.w(TAG, "getAccounts() fallback failed: ", e);
        }
        return new Account[] {};
    }

    @Override
    public AccessTokenData getAccessToken(Account account, String authTokenScope)
            throws AuthException {
        ThreadUtils.assertOnBackgroundThread();

        // Log OAuthLogin scope specifically - this is required for web sign-in
        boolean isOAuthLoginScope = authTokenScope.contains("OAuthLogin") ||
                                     authTokenScope.contains("accounts.google.com");
        if (isOAuthLoginScope) {
            Log.i(TAG, "*** OAuthLogin scope requested! This is for web sign-in (cookies). Scope: %s",
                    authTokenScope);
        }

        Log.i(TAG, "Requesting token for scope '%s' account '%s' via GoogleAuthUtil (patched to microG)",
                authTokenScope, account.name);

        // GoogleAuthUtil has been Smali-patched to bind to app.revanced.android.gms
        // instead of com.google.android.gms, so this will go to microG
        try {
            String token = GoogleAuthUtil.getTokenWithNotification(
                    ContextUtils.getApplicationContext(), account, authTokenScope, null);

            if (token != null) {
                if (isOAuthLoginScope) {
                    Log.i(TAG, "*** OAuthLogin token SUCCESS! Web sign-in should work now.");
                    // CRITICAL: Extract and cache the real Gaia ID SYNCHRONOUSLY before returning.
                    // Multilogin will call getAccountGaiaId() immediately after this returns,
                    // so we must have the real Gaia ID cached or it will get a fake ID and fail.
                    extractAndCacheRealGaiaIdSync(account.name, token);
                }
                Log.i(TAG, "Successfully obtained access token via GoogleAuthUtil (microG)");
                return new AccessTokenData(token);
            }
        } catch (GoogleAuthException ex) {
            Log.w(TAG, "GoogleAuthException for scope '%s': %s", authTokenScope, ex.getMessage());
            // Use SERVICE_UNAVAILABLE (transient) instead of INVALID_GAIA_CREDENTIALS (persistent)
            // to prevent the AccountReconcilor from aborting cookie reconciliation
            throw new AuthException(
                    "Error while getting token for scope '" + authTokenScope + "'",
                    ex,
                    new GoogleServiceAuthError(
                            GoogleServiceAuthErrorState.SERVICE_UNAVAILABLE));
        } catch (IOException ex) {
            Log.w(TAG, "IOException for scope '%s': %s", authTokenScope, ex.getMessage());
            throw new AuthException(
                    "Error while getting token for scope '" + authTokenScope + "'",
                    ex,
                    new GoogleServiceAuthError(GoogleServiceAuthErrorState.CONNECTION_FAILED));
        }

        throw new AuthException(
                "Null token returned for scope '" + authTokenScope + "'",
                new RuntimeException("Null token"),
                new GoogleServiceAuthError(
                        GoogleServiceAuthErrorState.SERVICE_UNAVAILABLE));
    }

    @Override
    public void invalidateAccessToken(String authToken) throws AuthException {
        try {
            // Use GoogleAuthUtil to clear token - same as SystemAccountManagerDelegate
            GoogleAuthUtil.clearToken(ContextUtils.getApplicationContext(), authToken);
        } catch (GoogleAuthException ex) {
            throw new AuthException(
                    "Error while invalidating access token",
                    ex,
                    new GoogleServiceAuthError(
                            GoogleServiceAuthErrorState.INVALID_GAIA_CREDENTIALS));
        } catch (IOException ex) {
            throw new AuthException(
                    "Error while invalidating access token",
                    ex,
                    new GoogleServiceAuthError(GoogleServiceAuthErrorState.CONNECTION_FAILED));
        }
    }

    @Override
    public int hasCapability(@Nullable Account account, String capability) {
        // Check account features via AccountManager
        if (account != null && capability != null) {
            try {
                boolean hasFeature = mAccountManager
                        .hasFeatures(account, new String[] {capability}, null, null)
                        .getResult();
                return hasFeature ? AccountManagerDelegate.CapabilityResponse.YES
                        : AccountManagerDelegate.CapabilityResponse.NO;
            } catch (AuthenticatorException | IOException | OperationCanceledException e) {
                Log.e(TAG, "Error while checking capability: ", e);
            }
        }
        return AccountManagerDelegate.CapabilityResponse.EXCEPTION;
    }

    @SuppressLint("MissingPermission")
    @Override
    public void createAddAccountIntent(
            @Nullable String prefilledEmail, Callback<@Nullable Intent> callback) {
        AccountManagerCallback<Bundle> accountManagerCallback =
                accountManagerFuture -> {
                    try {
                        Bundle bundle = accountManagerFuture.getResult();
                        callback.onResult(bundle.getParcelable(AccountManager.KEY_INTENT));
                    } catch (OperationCanceledException | IOException | AuthenticatorException e) {
                        Log.e(TAG, "Error while creating an intent to add an account: ", e);
                        callback.onResult(null);
                    }
                };
        // Note: prefilledEmail is currently ignored for microG accounts
        mAccountManager.addAccount(
                mAccountType, null, null, null, null, accountManagerCallback, null);
    }

    @SuppressLint("MissingPermission")
    @Override
    public void updateCredentials(
            Account account, Activity activity, final @Nullable Callback<Boolean> callback) {
        ThreadUtils.assertOnUiThread();
        AccountManagerCallback<Bundle> realCallback =
                future -> {
                    Bundle bundle = null;
                    try {
                        bundle = future.getResult();
                    } catch (AuthenticatorException | IOException e) {
                        Log.e(TAG, "Error while update credentials: ", e);
                    } catch (OperationCanceledException e) {
                        Log.w(TAG, "Updating credentials was cancelled.");
                    }
                    boolean success =
                            bundle != null
                                    && bundle.getString(AccountManager.KEY_ACCOUNT_TYPE) != null;
                    if (callback != null) {
                        callback.onResult(success);
                    }
                };
        Bundle emptyOptions = new Bundle();
        mAccountManager.updateCredentials(
                account, "android", emptyOptions, activity, realCallback, null);
    }

    @Override
    public @Nullable GaiaId getAccountGaiaId(String accountEmail) {
        // Log stack trace to see WHO is calling this and WHEN
        Log.i(TAG, "*** getAccountGaiaId called for %s - stack trace:", accountEmail);
        for (StackTraceElement ste : Thread.currentThread().getStackTrace()) {
            if (ste.getClassName().contains("chromium") || ste.getClassName().contains("signin")) {
                Log.i(TAG, "    at %s.%s(%s:%d)",
                    ste.getClassName(), ste.getMethodName(), ste.getFileName(), ste.getLineNumber());
            }
        }

        // For ReVanced microG accounts, we can't call getUserData() due to
        // SecurityException (only the authenticator can read user data).
        if (REVANCED_ACCOUNT_TYPE.equals(mAccountType)) {
            String realGaiaId = fetchRealGaiaId(accountEmail);
            if (realGaiaId != null) {
                Log.i(TAG, "getAccountGaiaId: returning real gaia_id for ReVanced account %s",
                        accountEmail);
                return new GaiaId(realGaiaId);
            }
            // Fallback to fake ID - at least sign-in works
            String fakeGaiaId = generateFakeGaiaId(accountEmail);
            Log.i(TAG, "getAccountGaiaId: using fake gaia_id for ReVanced account %s: %s",
                    accountEmail, fakeGaiaId);
            return new GaiaId(fakeGaiaId);
        }

        // For upstream microG (replacing GMS), try normally
        try {
            Account[] accounts = mAccountManager.getAccountsByType(mAccountType);
            for (Account account : accounts) {
                if (account.name.equals(accountEmail)) {
                    String gaiaId = mAccountManager.getUserData(account, "gaia_id");
                    if (gaiaId != null) {
                        return new GaiaId(gaiaId);
                    }
                    return null;
                }
            }
        } catch (SecurityException e) {
            Log.w(TAG, "getAccountGaiaId failed: ", e);
        }
        return null;
    }

    /**
     * Fetch the REAL Gaia ID from Google's userinfo API.
     * This ensures we return the same ID that Chrome will get, preventing sign-out on restart.
     *
     * The flow is:
     * 1. Check SharedPreferences for cached Gaia ID
     * 2. If not cached, get an access token for userinfo scope via microG
     * 3. Call Google's userinfo API with the token
     * 4. Extract the Gaia ID from the response
     * 5. Cache it in SharedPreferences
     */
    private @Nullable String fetchRealGaiaId(String email) {
        SharedPreferences prefs = ContextUtils.getApplicationContext()
                .getSharedPreferences(GAIA_ID_PREFS_NAME, Context.MODE_PRIVATE);

        // First, check for REAL Gaia ID captured previously
        String realKey = REAL_GAIA_ID_PREFIX + email;
        String realGaiaId = prefs.getString(realKey, null);
        if (realGaiaId != null && !realGaiaId.isEmpty()) {
            Log.i(TAG, "*** Using CAPTURED real gaia_id for %s: %s", email, realGaiaId);
            return realGaiaId;
        }

        // Try to get Gaia ID from microG's ContentProvider
        String gaiaIdFromMicroG = getGaiaIdFromMicroGContentProvider(email);
        if (gaiaIdFromMicroG != null) {
            // Cache it for future use
            prefs.edit()
                .putString(realKey, gaiaIdFromMicroG)
                .putString(GAIA_ID_PREFIX + email, gaiaIdFromMicroG)
                .apply();
            Log.i(TAG, "*** Got Gaia ID from microG ContentProvider for %s: %s", email, gaiaIdFromMicroG);
            return gaiaIdFromMicroG;
        }

        // Check legacy cache key
        String prefsKey = GAIA_ID_PREFIX + email;
        String cachedGaiaId = prefs.getString(prefsKey, null);

        // Only use cached ID if it looks like a REAL Gaia ID (21 digits or less - Google IDs vary)
        if (cachedGaiaId != null && cachedGaiaId.length() <= 21 && cachedGaiaId.length() >= 10) {
            Log.i(TAG, "Using cached real gaia_id for %s: %s", email, cachedGaiaId);
            return cachedGaiaId;
        } else if (cachedGaiaId != null) {
            // Clear invalid cached ID (likely a fake one with wrong length)
            Log.w(TAG, "Clearing invalid cached gaia_id for %s (length=%d)",
                    email, cachedGaiaId.length());
            prefs.edit().remove(prefsKey).apply();
        }

        // Need to fetch from Google's API
        Log.i(TAG, "Fetching real Gaia ID from Google API for %s", email);

        try {
            // Get access token for userinfo scope
            Account account = new Account(email, mAccountType);
            String scope = "oauth2:https://www.googleapis.com/auth/userinfo.profile";
            String token = GoogleAuthUtil.getTokenWithNotification(
                    ContextUtils.getApplicationContext(), account, scope, null);

            if (token == null) {
                Log.w(TAG, "Failed to get userinfo token for %s", email);
                return null;
            }

            // Call Google's userinfo API
            URL url = new URL("https://www.googleapis.com/oauth2/v1/userinfo?alt=json");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Authorization", "Bearer " + token);
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);

            int responseCode = conn.getResponseCode();
            if (responseCode != 200) {
                Log.w(TAG, "Userinfo API returned %d for %s", responseCode, email);
                conn.disconnect();
                return null;
            }

            // Read response
            BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();
            conn.disconnect();

            // Parse JSON response to get Gaia ID
            JSONObject json = new JSONObject(response.toString());
            String gaiaId = json.optString("id", null);

            if (gaiaId != null && !gaiaId.isEmpty()) {
                // Cache the real Gaia ID
                prefs.edit().putString(prefsKey, gaiaId).apply();
                Log.i(TAG, "Fetched and cached real gaia_id for %s: %s", email, gaiaId);
                return gaiaId;
            } else {
                Log.w(TAG, "Userinfo response missing 'id' field for %s", email);
            }
        } catch (GoogleAuthException e) {
            Log.w(TAG, "GoogleAuthException fetching Gaia ID for %s: %s", email, e.getMessage());
        } catch (IOException e) {
            Log.w(TAG, "IOException fetching Gaia ID for %s: %s", email, e.getMessage());
        } catch (Exception e) {
            Log.w(TAG, "Error fetching Gaia ID for %s: %s", email, e.getMessage());
        }

        return null;
    }

    @Override
    public void confirmCredentials(
            Account account, @Nullable Activity activity, Callback<@Nullable Bundle> callback) {
        AccountManagerCallback<Bundle> accountManagerCallback =
                (accountManagerFuture) -> {
                    @Nullable Bundle result = null;
                    try {
                        result = accountManagerFuture.getResult();
                    } catch (Exception e) {
                        Log.e(TAG, "Error while confirming credentials: ", e);
                    }
                    callback.onResult(result);
                };
        mAccountManager.confirmCredentials(
                account, new Bundle(), activity, accountManagerCallback, null);
    }

    /**
     * Generate a fake but deterministic gaia_id based on email address.
     * This allows Chromium to proceed with account resolution without SecurityException.
     *
     * Fix for random sign-out: Persist generated Gaia IDs to SharedPreferences.
     * On app restart, Chromium compares the stored Gaia ID with the current one.
     * If they don't match (e.g., due to algorithm changes between builds),
     * Chromium signs out the user. By persisting the Gaia ID, we ensure consistency.
     */
    private static final String FAKE_GAIA_ID_PREFIX = "fake_gaia_id_";
    private static final String REAL_GAIA_ID_PREFIX = "real_gaia_id_";

    /**
     * Try to get the Gaia ID directly from microG's ContentProvider.
     * microG stores account metadata including the Gaia ID.
     */
    private @Nullable String getGaiaIdFromMicroGContentProvider(String email) {
        ContentResolver resolver = ContextUtils.getApplicationContext().getContentResolver();
        Uri uri = Uri.parse("content://" + REVANCED_AUTH_AUTHORITY);

        try {
            // Try "get_account_data" method
            Bundle extras = new Bundle();
            extras.putString("account_name", email);
            extras.putString("account_type", mAccountType);
            extras.putString("key", "gaia_id");

            Bundle result = resolver.call(uri, "get_account_data", mAccountType, extras);
            if (result != null) {
                String gaiaId = result.getString("gaia_id");
                if (gaiaId == null) gaiaId = result.getString("value");
                if (gaiaId == null) gaiaId = result.getString("result");
                if (gaiaId != null && !gaiaId.isEmpty()) {
                    Log.i(TAG, "ContentProvider get_account_data returned gaia_id: %s", gaiaId);
                    return gaiaId;
                }
                // Log what we got
                Log.i(TAG, "ContentProvider get_account_data result keys: %s", result.keySet());
            }

            // Try "getUserData" method (standard AccountManager method name)
            extras.putString("key", "GoogleUserId");
            result = resolver.call(uri, "getUserData", email, extras);
            if (result != null) {
                String gaiaId = result.getString("GoogleUserId");
                if (gaiaId == null) gaiaId = result.getString("value");
                if (gaiaId != null && !gaiaId.isEmpty()) {
                    Log.i(TAG, "ContentProvider getUserData returned gaia_id: %s", gaiaId);
                    return gaiaId;
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "Error getting Gaia ID from ContentProvider for %s: %s", email, e.getMessage());
        }

        return null;
    }

    /**
     * Extract the real Gaia ID SYNCHRONOUSLY from the OAuthLogin token.
     *
     * CRITICAL: This MUST be synchronous! The multilogin flow starts immediately
     * after the token is returned, and needs the REAL Gaia ID. If we extract
     * asynchronously, multilogin will use a fake ID and fail with kInvalidTokens.
     *
     * The OAuthLogin token might be a JWT containing the user ID. We try to decode it.
     * If that fails, we call Google's userinfo API synchronously.
     */
    private void extractAndCacheRealGaiaIdSync(String email, String token) {
        Log.i(TAG, "*** extractAndCacheRealGaiaIdSync: starting for %s", email);
        String gaiaId = null;

        // Method 1: Try to decode the token as JWT and extract 'sub' claim
        // OAuthLogin tokens from Google are often JWTs with the Gaia ID in the 'sub' field
        try {
            String[] parts = token.split("\\.");
            if (parts.length >= 2) {
                // JWT payload is base64url encoded
                String payload = parts[1];
                // Add padding if needed
                int padding = (4 - payload.length() % 4) % 4;
                payload = payload + "====".substring(0, padding);
                // Replace URL-safe chars
                payload = payload.replace('-', '+').replace('_', '/');

                byte[] decoded = android.util.Base64.decode(payload, android.util.Base64.DEFAULT);
                String payloadJson = new String(decoded, "UTF-8");
                JSONObject jwt = new JSONObject(payloadJson);

                // Try various claim names for Gaia ID
                gaiaId = jwt.optString("sub", null);
                if (gaiaId == null) gaiaId = jwt.optString("id", null);
                if (gaiaId == null) gaiaId = jwt.optString("user_id", null);
                if (gaiaId == null) gaiaId = jwt.optString("obfuscatedGaiaId", null);

                if (gaiaId != null && !gaiaId.isEmpty()) {
                    Log.i(TAG, "*** Extracted Gaia ID from JWT: %s", gaiaId);
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "JWT decode failed for %s: %s", email, e.getMessage());
        }

        // Method 2: Call userinfo API synchronously if JWT didn't work
        if (gaiaId == null || gaiaId.isEmpty()) {
            Log.i(TAG, "*** JWT decode didn't yield Gaia ID, trying userinfo API...");
            try {
                URL url = new URL("https://www.googleapis.com/oauth2/v3/userinfo");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setRequestProperty("Authorization", "Bearer " + token);
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(5000);

                int responseCode = conn.getResponseCode();
                if (responseCode == 200) {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                    StringBuilder response = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        response.append(line);
                    }
                    reader.close();
                    conn.disconnect();

                    JSONObject json = new JSONObject(response.toString());
                    gaiaId = json.optString("sub", null);
                    if (gaiaId == null) gaiaId = json.optString("id", null);
                    if (gaiaId != null) {
                        Log.i(TAG, "*** UserInfo API returned Gaia ID: %s", gaiaId);
                    }
                } else {
                    Log.w(TAG, "UserInfo API returned %d for %s", responseCode, email);
                    conn.disconnect();
                }
            } catch (Exception e) {
                Log.w(TAG, "UserInfo API error for %s: %s", email, e.getMessage());
            }
        }

        // Cache the real Gaia ID if we got one
        if (gaiaId != null && !gaiaId.isEmpty()) {
            SharedPreferences prefs = ContextUtils.getApplicationContext()
                    .getSharedPreferences(GAIA_ID_PREFS_NAME, Context.MODE_PRIVATE);
            prefs.edit()
                .putString(REAL_GAIA_ID_PREFIX + email, gaiaId)
                .putString(GAIA_ID_PREFIX + email, gaiaId)
                .apply();
            Log.i(TAG, "*** CACHED REAL Gaia ID for %s: %s (length=%d)", email, gaiaId, gaiaId.length());
        } else {
            Log.w(TAG, "*** FAILED to extract real Gaia ID for %s - multilogin will likely fail!", email);
        }
    }

    /**
     * Extract the real Gaia ID using a successful OAuth token and cache it (ASYNC version).
     * This is called when OAuthLogin succeeds during sign-in.
     *
     * Fix for random sign-out: Sets mGaiaExtractionInProgress flag to suppress
     * account change broadcasts while extraction is in progress. This prevents
     * Chrome from calling getAccountGaiaId() and getting a fake ID before we
     * have the real one cached.
     */
    private void extractAndCacheRealGaiaId(String email, String token) {
        // Mark extraction in progress to suppress account change broadcasts
        mGaiaExtractionInProgress = true;
        mGaiaExtractionStartTime = android.os.SystemClock.uptimeMillis();
        Log.i(TAG, "*** Starting Gaia ID extraction for %s (broadcasts suppressed)", email);

        // Run in background to avoid blocking
        new Thread(() -> {
            String gaiaId = null;

            // Try method 1: Google People API (most reliable)
            try {
                URL url = new URL("https://people.googleapis.com/v1/people/me?personFields=metadata&access_token=" + token);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("GET");
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(5000);

                int responseCode = conn.getResponseCode();
                if (responseCode == 200) {
                    BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                    StringBuilder response = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        response.append(line);
                    }
                    reader.close();
                    conn.disconnect();

                    // Parse response - resourceName contains "people/{gaiaId}"
                    JSONObject json = new JSONObject(response.toString());
                    String resourceName = json.optString("resourceName", null);
                    if (resourceName != null && resourceName.startsWith("people/")) {
                        gaiaId = resourceName.substring(7); // Remove "people/" prefix
                        Log.i(TAG, "*** People API returned Gaia ID for %s: %s", email, gaiaId);
                    }
                } else {
                    Log.w(TAG, "People API returned %d for %s", responseCode, email);
                    conn.disconnect();
                }
            } catch (Exception e) {
                Log.w(TAG, "People API error for %s: %s", email, e.getMessage());
            }

            // Try method 2: UserInfo endpoint with Bearer auth
            if (gaiaId == null) {
                try {
                    URL url = new URL("https://www.googleapis.com/oauth2/v3/userinfo");
                    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                    conn.setRequestMethod("GET");
                    conn.setRequestProperty("Authorization", "Bearer " + token);
                    conn.setConnectTimeout(5000);
                    conn.setReadTimeout(5000);

                    int responseCode = conn.getResponseCode();
                    if (responseCode == 200) {
                        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));
                        StringBuilder response = new StringBuilder();
                        String line;
                        while ((line = reader.readLine()) != null) {
                            response.append(line);
                        }
                        reader.close();
                        conn.disconnect();

                        JSONObject json = new JSONObject(response.toString());
                        gaiaId = json.optString("sub", null);
                        if (gaiaId == null) gaiaId = json.optString("id", null);
                        if (gaiaId != null) {
                            Log.i(TAG, "*** UserInfo API returned Gaia ID for %s: %s", email, gaiaId);
                        }
                    } else {
                        Log.w(TAG, "UserInfo API returned %d for %s", responseCode, email);
                        conn.disconnect();
                    }
                } catch (Exception e) {
                    Log.w(TAG, "UserInfo API error for %s: %s", email, e.getMessage());
                }
            }

            // Cache if we got a real Gaia ID
            if (gaiaId != null && !gaiaId.isEmpty()) {
                SharedPreferences prefs = ContextUtils.getApplicationContext()
                        .getSharedPreferences(GAIA_ID_PREFS_NAME, Context.MODE_PRIVATE);
                prefs.edit()
                    .putString(REAL_GAIA_ID_PREFIX + email, gaiaId)
                    .putString(GAIA_ID_PREFIX + email, gaiaId)
                    .apply();
                Log.i(TAG, "*** CAPTURED REAL Gaia ID for %s: %s (length=%d)",
                        email, gaiaId, gaiaId.length());
            } else {
                Log.w(TAG, "Could not extract real Gaia ID for %s via any method", email);
            }

            // Mark extraction complete - allow broadcasts again
            mGaiaExtractionInProgress = false;
            Log.i(TAG, "*** Gaia ID extraction complete for %s (broadcasts enabled, took %dms)",
                    email, android.os.SystemClock.uptimeMillis() - mGaiaExtractionStartTime);
        }).start();
    }

    private String generateFakeGaiaId(String email) {
        // Use DIFFERENT cache key for fake IDs to distinguish from real ones
        SharedPreferences prefs = ContextUtils.getApplicationContext()
                .getSharedPreferences(GAIA_ID_PREFS_NAME, Context.MODE_PRIVATE);
        String prefsKey = FAKE_GAIA_ID_PREFIX + email;
        String existingGaiaId = prefs.getString(prefsKey, null);

        // Only use cached fake ID if it's exactly 21 digits (correct format)
        if (existingGaiaId != null && existingGaiaId.length() == 21) {
            Log.i(TAG, "Using persisted fake gaia_id for %s: %s", email, existingGaiaId);
            return existingGaiaId;
        }

        // Generate new Gaia ID using SHA-256 - EXACTLY 21 digits
        String newGaiaId;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(email.getBytes());
            // Use first 8 bytes as a 64-bit number, then format to 21 digits
            long value = 0;
            for (int i = 0; i < 8 && i < digest.length; i++) {
                value = (value << 8) | (digest[i] & 0xFF);
            }
            // Ensure positive and format to exactly 21 digits
            // Use BigInteger for the modulo operation since 10^21 exceeds long range
            java.math.BigInteger bigValue = java.math.BigInteger.valueOf(Math.abs(value));
            java.math.BigInteger mod = new java.math.BigInteger("1000000000000000000000"); // 10^21
            newGaiaId = String.format("%021d", bigValue.mod(mod));
            // Truncate to exactly 21 digits if needed
            if (newGaiaId.length() > 21) {
                newGaiaId = newGaiaId.substring(newGaiaId.length() - 21);
            }
        } catch (NoSuchAlgorithmException e) {
            Log.w(TAG, "SHA-256 unavailable, falling back to simple hash");
            long hash = 0;
            for (int i = 0; i < email.length(); i++) {
                hash = 31 * hash + email.charAt(i);
            }
            newGaiaId = String.format("%021d", Math.abs(hash) % 1000000000000000000L);
            if (newGaiaId.length() > 21) {
                newGaiaId = newGaiaId.substring(newGaiaId.length() - 21);
            }
        }

        // Persist the new Gaia ID for future app restarts
        prefs.edit().putString(prefsKey, newGaiaId).apply();
        Log.i(TAG, "Generated and persisted new fake gaia_id for %s: %s (length=%d)",
                email, newGaiaId, newGaiaId.length());

        return newGaiaId;
    }
}
