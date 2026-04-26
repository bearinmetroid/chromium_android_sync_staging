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
import java.util.concurrent.ConcurrentHashMap;

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

    private static final long ACCOUNT_CHANGE_DEBOUNCE_MS = 2000;
    private long mLastAccountChangeTime = 0;

    private static final int CONTENT_PROVIDER_MAX_RETRIES = 3;
    private static final long CONTENT_PROVIDER_RETRY_DELAY_MS = 100;

    // for real Gaia IDs fetched from Google's userinfo API
    private static final ConcurrentHashMap<String, String> sRealGaiaIdCache = new ConcurrentHashMap<>();

    public MicroGAccountManagerDelegate() {
        mAccountManager = AccountManager.get(ContextUtils.getApplicationContext());
        mAccountType = detectAccountType();
        Log.w(TAG, "MicroGAccountManagerDelegate initialized, account type: %s", mAccountType);
    }

    private String detectAccountType() {
        try {
            ContextUtils.getApplicationContext()
                    .getPackageManager()
                    .getPackageInfo(REVANCED_GMS_PACKAGE, 0);
            Log.w(TAG, "ReVanced microG detected, using account type: %s", REVANCED_ACCOUNT_TYPE);
            return REVANCED_ACCOUNT_TYPE;
        } catch (PackageManager.NameNotFoundException e) {
            Log.w(TAG, "ReVanced microG not found, falling back to standard account type");
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
                        // service restart, or account operations. Without debouncing, each
                        long now = android.os.SystemClock.uptimeMillis();
                        if (now - mLastAccountChangeTime < ACCOUNT_CHANGE_DEBOUNCE_MS) {
                            Log.d(TAG, "Ignoring account change broadcast (debounced, %dms since last)",
                                    now - mLastAccountChangeTime);
                            return;
                        }
                        mLastAccountChangeTime = now;
                        Log.w(TAG, "Processing account change broadcast");
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
                Log.w(TAG, "ContentProvider returned %d accounts", accounts.length);
                return accounts;
            }
            // ContentProvider call might have set visibility - try AccountManager now
            Log.w(TAG, "ContentProvider returned 0 accounts, trying AccountManager");
        }

        // AccountManager directly (no permission gate — let it fail naturally)
        try {
            Account[] accounts = mAccountManager.getAccountsByType(mAccountType);
            Log.w(TAG, "AccountManager returned %d accounts of type '%s'",
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
            Log.w(TAG, "Trying fallback account enumeration for ReVanced microG");
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
                        Log.w(TAG, "GmsCore ContentProvider returned %d accounts (attempt %d)",
                                accounts.length, retry + 1);
                        return accounts;
                    }
                }
                // Result was empty or null, might be transient - retry
                if (retry < CONTENT_PROVIDER_MAX_RETRIES - 1) {
                    Log.w(TAG, "ContentProvider returned empty, retrying (attempt %d/%d)",
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
        Log.w(TAG, "GmsCore ContentProvider returned no accounts after %d attempts",
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
                Log.w(TAG, "Fallback found %d accounts of type '%s'", count, mAccountType);
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

        Log.w(TAG, "Requesting token for scope '%s' account '%s' via GoogleAuthUtil (patched to microG)",
                authTokenScope, account.name);

        // GoogleAuthUtil has been Smali-patched to bind to app.revanced.android.gms
        // instead of com.google.android.gms, so this will go to microG
        try {
            String token = GoogleAuthUtil.getTokenWithNotification(
                    ContextUtils.getApplicationContext(), account, authTokenScope, null);

            if (token != null) {
                Log.w(TAG, "Successfully obtained access token via GoogleAuthUtil (microG)");

                // Fetch and cache the real Gaia ID if not already cached
                if (!sRealGaiaIdCache.containsKey(account.name)) {
                    fetchAndCacheRealGaiaId(account.name, token);
                }

                return new AccessTokenData(token);
            }
        } catch (GoogleAuthException ex) {
            Log.w(TAG, "GoogleAuthException for scope '%s': %s", authTokenScope, ex.getMessage());
            throw new AuthException(
                    "Error while getting token for scope '" + authTokenScope + "'",
                    ex,
                    new GoogleServiceAuthError(
                            GoogleServiceAuthErrorState.INVALID_GAIA_CREDENTIALS));
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
                        GoogleServiceAuthErrorState.INVALID_GAIA_CREDENTIALS));
    }

    /**
     * Fetch the real Gaia ID from Google's userinfo API and cache it.
     * This is called on a background thread after successfully obtaining an OAuth token.
     */
    private void fetchAndCacheRealGaiaId(String email, String accessToken) {
        try {
            URL url = new URL("https://www.googleapis.com/oauth2/v3/userinfo");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setRequestProperty("Authorization", "Bearer " + accessToken);
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

                // Parse JSON to extract "sub" field (the real Gaia ID)
                String json = response.toString();
                String realGaiaId = extractSubFromJson(json);
                if (realGaiaId != null && !realGaiaId.isEmpty()) {
                    sRealGaiaIdCache.put(email, realGaiaId);
                    Log.w(TAG, "Cached real Gaia ID for %s: %s", email, realGaiaId);
                } else {
                    Log.w(TAG, "Failed to extract Gaia ID from userinfo response");
                }
            } else {
                Log.w(TAG, "Userinfo request failed with code %d", responseCode);
            }
            conn.disconnect();
        } catch (Exception e) {
            Log.w(TAG, "Failed to fetch real Gaia ID: %s", e.getMessage());
        }
    }

    /**
     * Simple JSON parser to extract the "sub" field value.
     * Format: {"sub":"123456789012345678901",...}
     */
    private String extractSubFromJson(String json) {
        // Look for "sub":"<value>"
        int subIndex = json.indexOf("\"sub\"");
        if (subIndex < 0) return null;

        int colonIndex = json.indexOf(':', subIndex);
        if (colonIndex < 0) return null;

        int startQuote = json.indexOf('"', colonIndex);
        if (startQuote < 0) return null;

        int endQuote = json.indexOf('"', startQuote + 1);
        if (endQuote < 0) return null;

        return json.substring(startQuote + 1, endQuote);
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

        // check if we have a cached real Gaia ID (fetched from userinfo API)
        String cachedRealId = sRealGaiaIdCache.get(accountEmail);
        if (cachedRealId != null) {
                    accountEmail, cachedRealId);
            return new GaiaId(cachedRealId);
        }


        // For ReVanced microG accounts, try to fetch the real Gaia ID synchronously
        if (REVANCED_ACCOUNT_TYPE.equals(mAccountType)) {
            // to fetch real Gaia ID from userinfo API
            String realGaiaId = fetchRealGaiaIdSync(accountEmail);
            if (realGaiaId != null && !realGaiaId.isEmpty()) {
                sRealGaiaIdCache.put(accountEmail, realGaiaId);
                        accountEmail, realGaiaId);
                return new GaiaId(realGaiaId);
            }

            // Fallback to fake ID if real fetch fails
            String fakeGaiaId = generateFakeGaiaId(accountEmail);
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
     * Fetch the real Gaia ID synchronously.
     *
     * Strategy: Use OAuthLogin token and call the tokeninfo endpoint to get the Gaia ID.
     *
     * IMPORTANT: GoogleAuthUtil requires accounts with type "com.google", not "app.revanced".
     * Even though we're using ReVanced microG (which uses app.revanced internally), the
     * GoogleAuthUtil API expects the standard Google account type. The Smali patches redirect
     * the RPC to app.revanced.android.gms, but the account type check is done locally.
     *
     * This is called from getAccountGaiaId when we don't have a cached ID.
     */
    private String fetchRealGaiaIdSync(String accountEmail) {

        try {
            // GoogleAuthUtil checks account type locally before making the RPC call.
            // It only accepts "com.google" accounts, even though the actual RPC goes
            // to ReVanced microG via Smali patches.
            Account account = new Account(accountEmail, GOOGLE_ACCOUNT_TYPE);
            Log.w(TAG, "fetchRealGaiaIdSync: created account with type '%s' for %s",
                    GOOGLE_ACCOUNT_TYPE, accountEmail);

            // Strategy 1: Get OAuthLogin token and use tokeninfo endpoint
            // The OAuthLogin scope works with microG, and tokeninfo returns user_id (Gaia ID)
            String token = null;
            try {
                token = GoogleAuthUtil.getTokenWithNotification(
                        ContextUtils.getApplicationContext(),
                        account,
                        "oauth2:https://www.google.com/accounts/OAuthLogin",
                        null);
                Log.w(TAG, "fetchRealGaiaIdSync: got OAuthLogin token for %s", accountEmail);
            } catch (Exception e) {
                Log.w(TAG, "fetchRealGaiaIdSync: OAuthLogin token failed for %s: %s",
                        accountEmail, e.getMessage());
            }

            if (token != null) {
                // Call tokeninfo endpoint to get user_id (which is the Gaia ID)
                String gaiaId = getGaiaIdFromTokenInfo(token, accountEmail);
                if (gaiaId != null) {
                    return gaiaId;
                }
            }

            // Strategy 2: Try email scope (more limited, but may work)
            try {
                token = GoogleAuthUtil.getTokenWithNotification(
                        ContextUtils.getApplicationContext(),
                        account,
                        "oauth2:email",
                        null);
                Log.w(TAG, "fetchRealGaiaIdSync: got email token for %s", accountEmail);
                if (token != null) {
                    String gaiaId = getGaiaIdFromTokenInfo(token, accountEmail);
                    if (gaiaId != null) {
                        return gaiaId;
                    }
                }
            } catch (Exception e) {
                Log.w(TAG, "fetchRealGaiaIdSync: email token failed for %s: %s",
                        accountEmail, e.getMessage());
            }

            // Strategy 3: Try openid scope to get ID token with sub claim
            try {
                token = GoogleAuthUtil.getTokenWithNotification(
                        ContextUtils.getApplicationContext(),
                        account,
                        "oauth2:openid",
                        null);
                Log.w(TAG, "fetchRealGaiaIdSync: got openid token for %s", accountEmail);
                if (token != null) {
                    // If it's a JWT, decode the sub claim
                    String gaiaId = extractSubFromJwt(token);
                    if (gaiaId != null) {
                                accountEmail, gaiaId);
                        return gaiaId;
                    }
                    // Otherwise try tokeninfo
                    gaiaId = getGaiaIdFromTokenInfo(token, accountEmail);
                    if (gaiaId != null) {
                        return gaiaId;
                    }
                }
            } catch (Exception e) {
                Log.w(TAG, "fetchRealGaiaIdSync: openid token failed for %s: %s",
                        accountEmail, e.getMessage());
            }

        } catch (Exception e) {
            Log.w(TAG, "fetchRealGaiaIdSync failed for %s: %s", accountEmail, e.getMessage());
        }

        return null;
    }

    /**
     * Call Google's tokeninfo endpoint to get the user_id (Gaia ID) from an access token.
     */
    private String getGaiaIdFromTokenInfo(String accessToken, String accountEmail) {
        try {
            URL url = new URL("https://www.googleapis.com/oauth2/v3/tokeninfo?access_token=" + accessToken);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);

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

                // Parse JSON to extract "sub" field (the Gaia ID in v3 API)
                String json = response.toString();
                Log.w(TAG, "tokeninfo response for %s: %s", accountEmail, json);

                // "sub" first (v3 tokeninfo), then "user_id" (v1)
                String gaiaId = extractFieldFromJson(json, "sub");
                if (gaiaId == null) {
                    gaiaId = extractFieldFromJson(json, "user_id");
                }

                if (gaiaId != null && !gaiaId.isEmpty()) {
                            accountEmail, gaiaId);
                    return gaiaId;
                }
            } else {
                Log.w(TAG, "tokeninfo API returned %d for %s", responseCode, accountEmail);
            }
            conn.disconnect();
        } catch (Exception e) {
            Log.w(TAG, "getGaiaIdFromTokenInfo failed for %s: %s", accountEmail, e.getMessage());
        }
        return null;
    }

    /**
     * Extract the "sub" claim from a JWT token (ID token).
     * JWT format: header.payload.signature, where payload is base64-encoded JSON.
     */
    private String extractSubFromJwt(String token) {
        try {
            // JWT has 3 parts separated by dots
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                return null; // Not a JWT
            }

            // Decode the payload (middle part)
            String payload = new String(android.util.Base64.decode(parts[1],
                    android.util.Base64.URL_SAFE | android.util.Base64.NO_PADDING | android.util.Base64.NO_WRAP));

            // Extract "sub" field
            return extractFieldFromJson(payload, "sub");
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Extract the "id" field from userinfo JSON response.
     * Format: {"id":"123456789012345678901",...}
     */
    private String extractIdFromJson(String json) {
        // "id" first (v1 API)
        String id = extractFieldFromJson(json, "id");
        if (id != null) return id;

        // "sub" (v3 API)
        return extractFieldFromJson(json, "sub");
    }

    private String extractFieldFromJson(String json, String fieldName) {
        String searchStr = "\"" + fieldName + "\"";
        int fieldIndex = json.indexOf(searchStr);
        if (fieldIndex < 0) return null;

        int colonIndex = json.indexOf(':', fieldIndex);
        if (colonIndex < 0) return null;

        int startQuote = json.indexOf('"', colonIndex);
        if (startQuote < 0) return null;

        int endQuote = json.indexOf('"', startQuote + 1);
        if (endQuote < 0) return null;

        return json.substring(startQuote + 1, endQuote);
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
     * Fix for random sign-out: Use SHA-256 instead of simple hash to prevent collisions.
     * Hash collisions could cause Chromium to treat different accounts as the same,
     * leading to authentication confusion and sign-out.
     */
    private String generateFakeGaiaId(String email) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(email.getBytes());
            // Convert bytes to numeric string - Gaia IDs are exactly 21 digits
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < digest.length && sb.length() < 21; i++) {
                int val = digest[i] & 0xFF;
                if (val < 10) sb.append('0');
                sb.append(val);
            }
            // Pad if too short (shouldn't happen with SHA-256)
            while (sb.length() < 21) {
                sb.insert(0, '0');
            }
            // Truncate to exactly 21 digits (standard Gaia ID length)
            if (sb.length() > 21) {
                sb.setLength(21);
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            // Fallback to simple hash if SHA-256 unavailable (shouldn't happen)
            Log.w(TAG, "SHA-256 unavailable, falling back to simple hash");
            long hash = 0;
            for (int i = 0; i < email.length(); i++) {
                hash = 31 * hash + email.charAt(i);
            }
            return String.format("%021d", Math.abs(hash) % 1000000000000000000L);
        }
    }
}
