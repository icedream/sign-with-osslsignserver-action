# sign.ps1 - signs an artifact via osslsignserver REST API (Windows / PowerShell)
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

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# Mask the secret immediately so it never appears in logs
# ---------------------------------------------------------------------------
Write-Output "::add-mask::$($env:OSSLSIGN_SECRET)"

# ---------------------------------------------------------------------------
# Validate required inputs
# ---------------------------------------------------------------------------
foreach ($var in @('OSSLSIGN_URL', 'OSSLSIGN_SECRET', 'OSSLSIGN_PROFILE', 'OSSLSIGN_FILE')) {
    if ([string]::IsNullOrEmpty((Get-Item "Env:$var" -ErrorAction SilentlyContinue).Value)) {
        Write-Output "::error::$var must be set"
        exit 1
    }
}

$Timeout = if ($env:OSSLSIGN_TIMEOUT) { $env:OSSLSIGN_TIMEOUT } else { '120' }

if (-not (Test-Path -LiteralPath $env:OSSLSIGN_FILE -PathType Leaf)) {
    Write-Output "::error::File not found: $($env:OSSLSIGN_FILE)"
    exit 1
}

# Determine output path (default: overwrite in-place)
$Output = if ($env:OSSLSIGN_OUTPUT) { $env:OSSLSIGN_OUTPUT } else { $env:OSSLSIGN_FILE }

# ---------------------------------------------------------------------------
# Compute SHA-256 of the file being signed
# ---------------------------------------------------------------------------
$FileSha256 = (Get-FileHash -LiteralPath $env:OSSLSIGN_FILE -Algorithm SHA256).Hash.ToLower()

# ---------------------------------------------------------------------------
# Generate timestamp (ISO 8601 UTC, RFC 3339)
# ---------------------------------------------------------------------------
$Timestamp = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')

# ---------------------------------------------------------------------------
# Generate a unique request ID
# ---------------------------------------------------------------------------
$RequestId = [Guid]::NewGuid().ToString().ToLower()

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
$Endpoint  = $env:OSSLSIGN_URL.TrimEnd('/') + '/v1/sign'
$Canonical = "POST`n/v1/sign`n${Timestamp}`n${RequestId}`n${FileSha256}`n$($env:OSSLSIGN_PROFILE)`n"

$SecretBytes    = [System.Text.Encoding]::UTF8.GetBytes($env:OSSLSIGN_SECRET)
$CanonicalBytes = [System.Text.Encoding]::UTF8.GetBytes($Canonical)
$Hmac           = New-Object System.Security.Cryptography.HMACSHA256
$Hmac.Key       = $SecretBytes
$Signature      = [System.BitConverter]::ToString($Hmac.ComputeHash($CanonicalBytes)).Replace('-', '').ToLower()

# ---------------------------------------------------------------------------
# Send the signing request
# ---------------------------------------------------------------------------
Write-Output "::group::Signing $($env:OSSLSIGN_FILE)"
Write-Output "  Endpoint : $Endpoint"
Write-Output "  Profile  : $($env:OSSLSIGN_PROFILE)"
Write-Output "  File SHA : $FileSha256"
Write-Output "  Request  : $RequestId"
Write-Output "  Timestamp: $Timestamp"
Write-Output "  Output   : $Output"

# Write response body and headers to temp files for retry logic
$TmpResponse = [System.IO.Path]::GetTempFileName()
$TmpHeaders = [System.IO.Path]::GetTempFileName()

function Send-Request {
    param(
        [string]$Endpoint,
        [string]$Timestamp,
        [string]$RequestId,
        [string]$Signature,
        [string]$SigningProfile,
        [string]$File,
        [string]$Timeout,
        [string]$Description,
        [string]$DescriptionUrl,
        [string]$ResponseFile,
        [string]$HeadersFile
    )

    $CurlArgs = @(
        '--silent',
        '--show-error',
        '--max-time', $Timeout,
        '--output', $ResponseFile,
        '--write-out', '%{http_code}',
        '--dump-header', $HeadersFile,
        '-H', "X-Timestamp: $Timestamp",
        '-H', "X-Request-ID: $RequestId",
        '-H', "X-Request-Signature: $Signature",
        '-F', "profile=$SigningProfile",
        '-F', "file=@$File"
    )

    if (-not [string]::IsNullOrEmpty($Description)) {
        $CurlArgs += @('-F', "description=$Description")
    }
    if (-not [string]::IsNullOrEmpty($DescriptionUrl)) {
        $CurlArgs += @('-F', "description_url=$DescriptionUrl")
    }

    $CurlArgs += $Endpoint

    $HttpStatus = & curl.exe @CurlArgs
    return $HttpStatus
}

$RetryCount = 0
$MaxRetries = 10
$RetryDelay = 1

while ($RetryCount -lt $MaxRetries) {
    $HttpStatus = Send-Request -Endpoint $Endpoint -Timestamp $Timestamp -RequestId $RequestId -Signature $Signature -SigningProfile $OSSLSIGN_PROFILE -File $OSSLSIGN_FILE -Timeout $Timeout -Description $OSSLSIGN_DESCRIPTION -DescriptionUrl $OSSLSIGN_DESCRIPTION_URL -ResponseFile $TmpResponse -HeadersFile $TmpHeaders

    $RetryCount++
    Write-Output "  Attempt $RetryCount/$MaxRetries - HTTP $HttpStatus"

    if ($HttpStatus -eq '200') {
        Write-Output '::endgroup::'
        break
    }

    if ($HttpStatus -eq '503' -or $HttpStatus -eq '504') {
        # Extract Retry-After header if present
        $RetryDelay = $RetryDelay * 2
        if ($RetryDelay -gt 60) { $RetryDelay = 60 }

        if (Test-Path $TmpHeaders) {
            $RetryAfterMatch = Select-String -Path $TmpHeaders -Pattern 'Retry-After:\s*(\d+)'
            if ($RetryAfterMatch.Success) {
                $parsed = [int]$RetryAfterMatch.Matches.Groups[1].Value
                if ($parsed -gt 0 -and $parsed -gt $RetryDelay) {
                    $RetryDelay = $parsed
                }
            }
        }

        Write-Output "  Retrying in ${RetryDelay}s (503/504)"
        Start-Sleep -Seconds $RetryDelay
        continue
    }

    Write-Output '::endgroup::'
    Write-Output "::error::Signing failed with HTTP $HttpStatus"
    Write-Output 'Server response:'
    Get-Content -LiteralPath $TmpResponse -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $TmpResponse -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $TmpHeaders -ErrorAction SilentlyContinue
    exit 1
}

Write-Output "  HTTP status: $HttpStatus"
Write-Output '::endgroup::'

# Move the signed artifact to the desired output path
if ($TmpResponse -ne $Output) {
    Move-Item -LiteralPath $TmpResponse -Destination $Output -Force
}

# Resolve to an absolute path for the output variable
$AbsOutput = (Resolve-Path -LiteralPath $Output).Path

Add-Content -Path $env:GITHUB_OUTPUT -Value "signed-file=$AbsOutput"
Write-Output "Signed artifact saved to: $AbsOutput"
