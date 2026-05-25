#!/bin/bash
# sign.sh — signs an artifact via osslsignserver REST API
# Called by action.yml; all configuration arrives via environment variables.
#
# Required env:
#   OSSLSIGN_URL      Base URL of the osslsignserver instance
#   OSSLSIGN_SECRET   HMAC shared secret (apiKeyHMACSecret on the server)
#   OSSLSIGN_PROFILE  Signing profile name
#   OSSLSIGN_FILE     Path to the artifact to sign
#
# Optional env:
#   OSSLSIGN_OUTPUT   Output path (default: overwrite OSSLSIGN_FILE in-place)
#   OSSLSIGN_TIMEOUT  curl --max-time seconds (default: 120)

set -eo pipefail

# ---------------------------------------------------------------------------
# Mask the secret immediately so it never appears in logs
# ---------------------------------------------------------------------------
echo "::add-mask::${OSSLSIGN_SECRET}"

# ---------------------------------------------------------------------------
# Validate required inputs
# ---------------------------------------------------------------------------
: "${OSSLSIGN_URL:?OSSLSIGN_URL must be set}"
: "${OSSLSIGN_SECRET:?OSSLSIGN_SECRET must be set}"
: "${OSSLSIGN_PROFILE:?OSSLSIGN_PROFILE must be set}"
: "${OSSLSIGN_FILE:?OSSLSIGN_FILE must be set}"

TIMEOUT="${OSSLSIGN_TIMEOUT:-120}"

if [ ! -f "$OSSLSIGN_FILE" ]; then
  echo "::error::File not found: $OSSLSIGN_FILE"
  exit 1
fi

# Determine output path (default: overwrite in-place)
OUTPUT="${OSSLSIGN_OUTPUT:-$OSSLSIGN_FILE}"

# ---------------------------------------------------------------------------
# Compute SHA-256 of the file being signed
# ---------------------------------------------------------------------------
if command -v sha256sum >/dev/null 2>&1; then
  FILE_SHA256=$(sha256sum "$OSSLSIGN_FILE" | cut -d' ' -f1)
elif command -v shasum >/dev/null 2>&1; then
  FILE_SHA256=$(shasum -a 256 "$OSSLSIGN_FILE" | cut -d' ' -f1)
else
  # openssl fallback (strips leading hash name)
  FILE_SHA256=$(openssl dgst -sha256 "$OSSLSIGN_FILE" | awk '{print $NF}')
fi

# ---------------------------------------------------------------------------
# Generate timestamp (ISO 8601 UTC, RFC 3339)
# ---------------------------------------------------------------------------
TIMESTAMP=$(date -u +'%Y-%m-%dT%H:%M:%SZ')

# ---------------------------------------------------------------------------
# Generate a unique request ID
# ---------------------------------------------------------------------------
if command -v uuidgen >/dev/null 2>&1; then
  REQUEST_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
elif command -v python3 >/dev/null 2>&1; then
  REQUEST_ID=$(python3 -c 'import uuid; print(uuid.uuid4())')
else
  # Fallback: use openssl to build a UUID-shaped identifier
  HEX=$(openssl rand -hex 16)
  REQUEST_ID="${HEX:0:8}-${HEX:8:4}-4${HEX:13:3}-${HEX:16:4}-${HEX:20:12}"
fi

# ---------------------------------------------------------------------------
# Build the canonical request string and compute HMAC-SHA256 signature
#
# Format (each field followed by \n, including the last):
#   POST\n
#   /v1/sign\n
#   {timestamp}\n
#   {request-id}\n
#   {file-sha256-hex}\n
#   {profile}\n
# ---------------------------------------------------------------------------
ENDPOINT="${OSSLSIGN_URL%/}/v1/sign"

# Pipe the canonical string directly into openssl to preserve the trailing
# newline — do not store in a shell variable (command substitution strips it).
SIGNATURE=$(printf 'POST\n/v1/sign\n%s\n%s\n%s\n%s\n' \
  "$TIMESTAMP" "$REQUEST_ID" "$FILE_SHA256" "$OSSLSIGN_PROFILE" | \
  openssl dgst -sha256 -hmac "$OSSLSIGN_SECRET" -hex | \
  awk '{print $NF}')

# ---------------------------------------------------------------------------
# Send the signing request
# ---------------------------------------------------------------------------
echo "::group::Signing $OSSLSIGN_FILE"
echo "  Endpoint : $ENDPOINT"
echo "  Profile  : $OSSLSIGN_PROFILE"
echo "  File SHA : $FILE_SHA256"
echo "  Request  : $REQUEST_ID"
echo "  Timestamp: $TIMESTAMP"
echo "  Output   : $OUTPUT"

# Write response body to a temp file so we can check the HTTP status
TMP_RESPONSE=$(mktemp)
trap 'rm -f "$TMP_RESPONSE"' EXIT

HTTP_STATUS=$(curl \
  --silent \
  --show-error \
  --max-time "$TIMEOUT" \
  --output "$TMP_RESPONSE" \
  --write-out '%{http_code}' \
  -H "X-Timestamp: $TIMESTAMP" \
  -H "X-Request-ID: $REQUEST_ID" \
  -H "X-Request-Signature: $SIGNATURE" \
  -F "profile=$OSSLSIGN_PROFILE" \
  -F "file=@$OSSLSIGN_FILE" \
  "$ENDPOINT") || {
  echo "::endgroup::"
  echo "::error::curl failed — check the server URL and network connectivity"
  exit 1
}

echo "  HTTP status: $HTTP_STATUS"
echo "::endgroup::"

if [ "$HTTP_STATUS" != "200" ]; then
  echo "::error::Signing failed with HTTP $HTTP_STATUS"
  # Print response body (likely a JSON error) without leaking secrets
  echo "Server response:"
  cat "$TMP_RESPONSE" 2>/dev/null || true
  echo
  exit 1
fi

# Move the signed artifact to the desired output path
if [ "$TMP_RESPONSE" != "$OUTPUT" ]; then
  mv "$TMP_RESPONSE" "$OUTPUT"
  trap - EXIT  # disarm the cleanup trap; file is now at OUTPUT
fi

# Resolve to an absolute path for the output variable
ABS_OUTPUT=$(realpath "$OUTPUT" 2>/dev/null || echo "$OUTPUT")

echo "signed-file=$ABS_OUTPUT" >> "$GITHUB_OUTPUT"
echo "✓ Signed artifact saved to: $ABS_OUTPUT"
