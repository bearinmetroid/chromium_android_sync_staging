# Ultimatum Chromium 147 - microG Integration Patches

This document describes all patches applied to enable Google account sign-in and sync functionality using microG (ReVanced GMS) instead of Google Play Services.

## Overview

These patches enable Chromium to work with microG by:
1. Adding a custom `MicroGAccountManagerDelegate` that communicates with ReVanced microG
2. Fixing Gaia ID handling to prevent sign-out issues
3. Adding Smali patches to redirect GoogleAuthUtil to microG
4. Adding email fallback to prevent sign-out when Gaia IDs don't match

## Files Modified/Added

### New Files

#### `components/signin/public/android/java/src/org/chromium/components/signin/MicroGAccountManagerDelegate.java`
Custom AccountManagerDelegate implementation for microG integration.

**Key Features:**
- Detects ReVanced microG via package check (`app.revanced.android.gms`)
- Uses `app.revanced` account type instead of `com.google`
- Fetches accounts via ContentProvider (`content://app.revanced.android.gms.auth.accounts`)
- Routes OAuth token requests through patched GoogleAuthUtil to microG
- Extracts and caches real Gaia IDs to prevent multilogin failures
- Suppresses account change broadcasts during Gaia ID extraction

**Critical Methods:**
- `getAccessToken()`: Requests OAuth tokens via GoogleAuthUtil (patched to microG)
- `extractAndCacheRealGaiaIdSync()`: Synchronously extracts real Gaia ID from JWT token before multilogin runs
- `getAccountGaiaId()`: Returns cached real Gaia ID or generates consistent fake ID
- `fetchRealGaiaId()`: Fetches Gaia ID from Google's userinfo API

#### `chrome/android/java/src/org/chromium/chrome/browser/sync/MicroGTrustedVaultBackend.java`
Stub implementation of TrustedVaultBackend for microG compatibility.

### Modified Files

#### `chrome/android/java/src/org/chromium/chrome/browser/signin/SigninManagerImpl.java`
**Change:** Added email fallback in `onCoreAccountInfosChanged()` to prevent sign-out when Gaia IDs don't match.

```java
// PATCH: For microG accounts, Gaia ID from stored account may differ from device accounts.
// Fall back to email matching to prevent sign-out when using fake/mismatched Gaia IDs.
if (AccountUtils.findAccountByEmail(accounts, primaryAccountInfo.getEmail()) != null) {
    Log.i(TAG, "Primary account Gaia ID mismatch, but email found - keeping signed in (microG workaround)");
    seedThenReloadAllAccountsFromSystem(accounts, CoreAccountInfo.getIdFrom(primaryAccountInfo));
    return;
}
```

**Why:** Chrome stores the real Gaia ID obtained during sign-in, but `getAccountGaiaId()` may return a different (fake) ID on app restart. Without this fallback, Chrome signs out because it can't find a matching account.

#### `components/signin/public/android/java/src/org/chromium/components/signin/AccountManagerFacadeProvider.java`
**Change:** Added logic to detect microG and instantiate `MicroGAccountManagerDelegate` instead of `SystemAccountManagerDelegate`.

#### `components/signin/public/android/BUILD.gn`
**Change:** Added `MicroGAccountManagerDelegate.java` to the build.

#### `chrome/android/chrome_java_sources.gni`
**Change:** Added `MicroGTrustedVaultBackend.java` to the build.

#### `chrome/browser/extensions/extension_browser_window_helper.cc`
**Change:** Added null pointer check to prevent crash when `GetNativeWindow()` returns null on Android.

```cpp
if (!browser_->window() || !browser_->window()->GetNativeWindow()) {
    return;
}
```

## Smali Patches Required

After building the APK, the following Smali patch must be applied to redirect GoogleAuthUtil to microG:

### `co4.smali` (GoogleAuthUtil wrapper class)
**Change:** Replace GMS package name with ReVanced microG package.

```smali
# Before:
const-string v1, "com.google.android.gms"

# After:
const-string v1, "app.revanced.android.gms"
```

### How to Apply Smali Patches

```bash
# 1. Extract APK
unzip ChromePublic.apk -d apk_contents

# 2. Decompile DEX
baksmali d apk_contents/classes.dex -o smali_out

# 3. Apply patch
sed -i 's/const-string v1, "com\.google\.android\.gms"/const-string v1, "app.revanced.android.gms"/g' smali_out/co4.smali

# 4. Reassemble DEX
smali a smali_out -o classes_patched.dex
cp classes_patched.dex apk_contents/classes.dex

# 5. Repack APK
cd apk_contents
zip -r ../patched.apk .
cd ..

# 6. Align and sign
zipalign -f -p 4 patched.apk aligned.apk
apksigner sign --ks debug.keystore --ks-pass pass:android --out final.apk aligned.apk
```

## Known Issues & Solutions

### Issue 1: UNREGISTERED_ON_API_CONSOLE Error
**Symptom:** OAuth token requests fail with "This android application is not registered to use OAuth2.0"

**Cause:** GoogleAuthUtil is binding to real GMS instead of microG.

**Solution:** Apply the Smali patch to redirect to `app.revanced.android.gms`.

### Issue 2: Sign-out on App Restart
**Symptom:** User gets signed out when reopening the app.

**Cause:** Chrome stores real Gaia ID, but `getAccountGaiaId()` returns fake ID on restart.

**Solution:** Email fallback in `SigninManagerImpl.onCoreAccountInfosChanged()`.

### Issue 3: google.com/youtube.com Sign-out
**Symptom:** Web sign-in works initially but signs out after a while.

**Cause:** Multilogin API receives fake Gaia IDs that don't match OAuth tokens.

**Solution:** Synchronous Gaia ID extraction in `extractAndCacheRealGaiaIdSync()` before multilogin runs.

### Issue 4: Google Bot Detection / CAPTCHA
**Symptom:** Google shows "unusual traffic" CAPTCHA and signs out user.

**Cause:** Server-side detection by Google, not a code issue.

**Solution:** Complete the CAPTCHA. The email fallback prevents app sign-out even when web session is invalidated.

## Build Requirements

- Chromium 147.0.7699.1 source
- Android NDK
- ReVanced microG installed on target device
- Debug keystore for signing (or release keystore)

## Testing Checklist

- [ ] Sign in to Chrome browser
- [ ] Verify sync works (bookmarks, extensions, etc.)
- [ ] Check google.com is signed in
- [ ] Check youtube.com is signed in
- [ ] Close and reopen app - should stay signed in
- [ ] Force stop app and reopen - should stay signed in
- [ ] If CAPTCHA appears, verify app doesn't sign out

## Credits

- Ultimatum Browser patches for Chromium 147
- ReVanced microG for Google Play Services replacement
