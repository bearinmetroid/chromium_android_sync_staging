#!/bin/bash
# apply_microg_smali_patch.sh
# Applies Smali patches to redirect GoogleAuthUtil to ReVanced microG
#
# Usage: ./apply_microg_smali_patch.sh <input.apk> <output.apk> <keystore> <keystore_pass>
#
# Requirements: baksmali, smali, zipalign, apksigner

set -e

if [ "$#" -lt 2 ]; then
    echo "Usage: $0 <input.apk> <output.apk> [keystore] [keystore_pass]"
    echo "  If keystore not provided, uses ~/.android/debug.keystore with password 'android'"
    exit 1
fi

INPUT_APK="$1"
OUTPUT_APK="$2"
KEYSTORE="${3:-$HOME/.android/debug.keystore}"
KEYSTORE_PASS="${4:-android}"

TEMP_DIR=$(mktemp -d)
trap "rm -rf $TEMP_DIR" EXIT

echo "=== microG Smali Patcher for Ultimatum ==="
echo "Input: $INPUT_APK"
echo "Output: $OUTPUT_APK"
echo "Keystore: $KEYSTORE"
echo ""

# Extract APK
echo "[1/6] Extracting APK..."
unzip -q "$INPUT_APK" -d "$TEMP_DIR/apk"

# Decompile DEX
echo "[2/6] Decompiling classes.dex..."
baksmali d "$TEMP_DIR/apk/classes.dex" -o "$TEMP_DIR/smali"

# Apply patches
echo "[3/6] Applying Smali patches..."

# Patch 1: Redirect GoogleAuthUtil to microG
if grep -q 'const-string v1, "com\.google\.android\.gms"' "$TEMP_DIR/smali/co4.smali" 2>/dev/null; then
    sed -i 's/const-string v1, "com\.google\.android\.gms"/const-string v1, "app.revanced.android.gms"/g' "$TEMP_DIR/smali/co4.smali"
    echo "  - Patched co4.smali (GoogleAuthUtil -> microG)"
else
    echo "  - co4.smali already patched or not found"
fi

# Verify patch
if grep -q 'app.revanced.android.gms' "$TEMP_DIR/smali/co4.smali" 2>/dev/null; then
    echo "  - Verified: microG binding in place"
else
    echo "  - WARNING: Could not verify patch!"
fi

# Reassemble DEX
echo "[4/6] Reassembling DEX..."
smali a "$TEMP_DIR/smali" -o "$TEMP_DIR/classes_patched.dex"
cp "$TEMP_DIR/classes_patched.dex" "$TEMP_DIR/apk/classes.dex"

# Repack APK
echo "[5/6] Repacking APK..."
rm -rf "$TEMP_DIR/apk/META-INF"
cd "$TEMP_DIR/apk"
zip -r -q -0 "$TEMP_DIR/patched.apk" resources.arsc assets/ lib/ 2>/dev/null || true
zip -r -q -9 "$TEMP_DIR/patched.apk" . -x "resources.arsc" -x "assets/*" -x "lib/*" -x "META-INF/*" 2>/dev/null
cd - > /dev/null

# Align and sign
echo "[6/6] Aligning and signing..."
zipalign -f -p 4 "$TEMP_DIR/patched.apk" "$TEMP_DIR/aligned.apk"
apksigner sign --ks "$KEYSTORE" --ks-pass "pass:$KEYSTORE_PASS" --out "$OUTPUT_APK" "$TEMP_DIR/aligned.apk"

# Verify
echo ""
echo "=== Complete ==="
echo "Output: $OUTPUT_APK"
echo "Size: $(ls -lh "$OUTPUT_APK" | awk '{print $5}')"
echo ""
echo "Signature:"
apksigner verify --print-certs "$OUTPUT_APK" 2>&1 | head -3
