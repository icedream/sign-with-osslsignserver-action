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
# Send the signing request with retry logic for 503/504
# ---------------------------------------------------------------------------
echo "::group::Signing $OSSLSIGN_FILE"
echo "  Endpoint : $ENDPOINT"
echo "  Profile  : $OSSLSIGN_PROFILE"
echo "  File SHA : $FILE_SHA256"
echo "  Request  : $REQUEST_ID"
echo "  Timestamp: $TIMESTAMP"
echo "  Output   : $OUTPUT"

# Write response body and headers to temp files for retry logic
TMP_RESPONSE=$(mktemp)
TMP_HEADERS=$(mktemp)
trap 'rm -f "$TMP_RESPONSE" "$TMP_HEADERS"' EXIT

RETRY_COUNT=0
MAX_RETRIES=10
RETRY_DELAY=1

send_request() {
  local args=(
    --silent
    --show-error
    --max-time "$TIMEOUT"
    --output "$TMP_RESPONSE"
    --write-out '%{http_code}'
    --dump-header "$TMP_HEADERS"
    -H "X-Timestamp: $TIMESTAMP"
    -H "X-Request-ID: $REQUEST_ID"
    -H "X-Request-Signature: $SIGNATURE"
    -F "profile=$OSSLSIGN_PROFILE"
    -F "file=@$OSSLSIGN_FILE"
  )

  # Add optional description fields if provided
  if [ -n "$OSSLSIGN_DESCRIPTION" ]; then
    args+=(-F "description=$OSSLSIGN_DESCRIPTION")
  fi
  if [ -n "$OSSLSIGN_DESCRIPTION_URL" ]; then
    args+=(-F "description_url=$OSSLSIGN_DESCRIPTION_URL")
  fi

  args+=("$ENDPOINT")

  curl "${args[@]}"
}

while [ "$RETRY_COUNT" -lt "$MAX_RETRIES" ]; do
  HTTP_STATUS=$(send_request) || {
    echo "::endgroup::"
    echo "::error::curl failed — check the server URL and network connectivity"
    exit 1
  }

  RETRY_COUNT=$((RETRY_COUNT + 1))
  echo "  Attempt $RETRY_COUNT/$MAX_RETRIES - HTTP $HTTP_STATUS"

  if [ "$HTTP_STATUS" = "200" ]; then
    echo "::endgroup::"
    break
  fi

  if [ "$HTTP_STATUS" = "503" ] || [ "$HTTP_STATUS" = "504" ]; then
    # Extract Retry-After header if present
    RETRY_AFTER=""
    if [ -f "$TMP_HEADERS" ]; then
      RETRY_AFTER=$(grep -i 'retry-after' "$TMP_HEADERS" | awk '{print $2}' | tr -d '\r') || true
    fi

    if [ -n "$RETRY_AFTER" ] && [ "$RETRY_AFTER" -gt 0 ] 2>/dev/null; then
      RETRY_DELAY="$RETRY_AFTER"
    else
      RETRY_DELAY=$((RETRY_DELAY * 2))
      [ "$RETRY_DELAY" -gt 60 ] && RETRY_DELAY=60
    fi

    echo "  Retrying in ${RETRY_DELAY}s (503/504)"
    sleep "$RETRY_DELAY"
    RETRY_DELAY=$((RETRY_DELAY * 2))
    [ "$RETRY_DELAY" -gt 60 ] && RETRY_DELAY=60
    continue
  fi

  echo "::endgroup::"
  echo "::error::Signing failed with HTTP $HTTP_STATUS"
  # Print response body (likely a JSON error) without leaking secrets
  echo "Server response:"
  cat "$TMP_RESPONSE" 2>/dev/null || true
  echo
  exit 1
done

echo "  HTTP status: $HTTP_STATUS"

# Move the signed artifact to the desired output path
if [ "$TMP_RESPONSE" != "$OUTPUT" ]; then
  mv "$TMP_RESPONSE" "$OUTPUT"
  trap - EXIT  # disarm the cleanup trap; file is now at OUTPUT
fi

# Resolve to an absolute path for the output variable
ABS_OUTPUT=$(realpath "$OUTPUT" 2>/dev/null || echo "$OUTPUT")

echo "signed-file=$ABS_OUTPUT" >> "$GITHUB_OUTPUT"
echo "✓ Signed artifact saved to: $ABS_OUTPUT"
