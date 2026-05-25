# sign-with-osslsignserver-action

[![CI](https://github.com/icedream/sign-with-osslsignserver-action/actions/workflows/test.yml/badge.svg)](https://github.com/icedream/sign-with-osslsignserver-action/actions/workflows/test.yml)

A GitHub Action that signs a built artifact by calling a running
[osslsignserver](https://github.com/icedream/go-osslsignserver) instance.

## Requirements

| Tool | Notes |
|------|-------|
| `curl` | Pre-installed on `ubuntu-*` and `macos-*` runners |
| `openssl` | Pre-installed on `ubuntu-*` and `macos-*` runners |

> **Windows runners are not supported**, use a Linux or macOS runner, or add
> a step that installs the required tools (e.g. Git Bash, WSL, or Cygwin).

## Quick start

```yaml
- uses: icedream/sign-with-osslsignserver-action@v1
  with:
    url: https://sign.example.com
    api-key-secret: ${{ secrets.OSSLSIGN_SECRET }}
    profile: windows-release
    file: dist/myapp.exe
```

## Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `url` | **yes** | | Base URL of the osslsignserver instance, e.g. `https://sign.example.com`. The `/v1/sign` path is appended automatically. |
| `api-key-secret` | **yes** | | HMAC shared secret. Must match the value in the server's `apiKeyHMACSecret` file. **Always store this in a GitHub Actions secret.** |
| `profile` | **yes** | | Signing profile name as configured on the server. |
| `file` | **yes** | | Path to the artifact to sign (relative to the workspace or absolute). |
| `output` | no | same as `file` | Where to save the signed artifact. Defaults to overwriting `file` in-place. |
| `timeout` | no | `120` | Maximum seconds to wait for the signing request. |

## Outputs

| Output | Description |
|--------|-------------|
| `signed-file` | Absolute path to the signed artifact. |

## Examples

### Sign and re-upload a Windows binary

```yaml
name: Build and Sign

on:
  push:
    tags: ['v*']

jobs:
  build-and-sign:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Build
        run: |
          go build -o dist/myapp.exe ./cmd/myapp

      - name: Sign
        uses: icedream/sign-with-osslsignserver-action@v1
        with:
          url: ${{ vars.OSSLSIGN_URL }}
          api-key-secret: ${{ secrets.OSSLSIGN_SECRET }}
          profile: windows-release
          file: dist/myapp.exe

      - name: Upload signed artifact
        uses: actions/upload-artifact@v4
        with:
          name: myapp-signed
          path: dist/myapp.exe
```

### Sign to a separate output path

```yaml
- name: Sign
  id: sign
  uses: icedream/sign-with-osslsignserver-action@v1
  with:
    url: ${{ vars.OSSLSIGN_URL }}
    api-key-secret: ${{ secrets.OSSLSIGN_SECRET }}
    profile: windows-release
    file: dist/myapp.exe
    output: dist/myapp-signed.exe

- name: Show signed path
  run: echo "Signed artifact is at ${{ steps.sign.outputs.signed-file }}"
```

### Sign multiple files

```yaml
- name: Sign installer
  uses: icedream/sign-with-osslsignserver-action@v1
  with:
    url: ${{ vars.OSSLSIGN_URL }}
    api-key-secret: ${{ secrets.OSSLSIGN_SECRET }}
    profile: windows-installer
    file: dist/setup.exe

- name: Sign driver
  uses: icedream/sign-with-osslsignserver-action@v1
  with:
    url: ${{ vars.OSSLSIGN_URL }}
    api-key-secret: ${{ secrets.OSSLSIGN_SECRET }}
    profile: windows-driver
    file: dist/driver.sys
```

### Complete release pipeline

```yaml
name: Release

on:
  push:
    tags: ['v*']

jobs:
  release:
    runs-on: ubuntu-latest
    permissions:
      contents: write

    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: stable

      - name: Build
        run: |
          GOOS=windows GOARCH=amd64 go build -o dist/myapp-windows-amd64.exe ./cmd/myapp
          GOOS=linux   GOARCH=amd64 go build -o dist/myapp-linux-amd64       ./cmd/myapp

      - name: Sign Windows binary
        uses: icedream/sign-with-osslsignserver-action@v1
        with:
          url: ${{ vars.OSSLSIGN_URL }}
          api-key-secret: ${{ secrets.OSSLSIGN_SECRET }}
          profile: windows-release
          file: dist/myapp-windows-amd64.exe

      - name: Create GitHub Release
        uses: softprops/action-gh-release@v2
        with:
          files: |
            dist/myapp-windows-amd64.exe
            dist/myapp-linux-amd64
```

## Security considerations

### Store secrets properly

Always pass `api-key-secret` through a GitHub Actions secret, never
hard-code it in your workflow file:

```yaml
# ✓ correct
api-key-secret: ${{ secrets.OSSLSIGN_SECRET }}

# ✗ never do this
api-key-secret: my-plain-text-secret
```

### How authentication works

The action uses **HMAC-SHA256 request signing** as implemented by osslsignserver:

1. Computes SHA-256 of the artifact.
2. Generates an ISO 8601 UTC timestamp and a unique request ID.
3. Constructs a canonical request string and signs it with the shared secret.
4. Sends `X-Timestamp`, `X-Request-ID`, and `X-Request-Signature` headers.

The server validates the signature and enforces a timestamp skew window to
prevent replay attacks.

### Network access

The signing server must be reachable from the GitHub Actions runner. Common
options:

- A publicly accessible server protected by the HMAC secret.
- A server on a private network, accessed via a VPN step or
  [GitHub's larger runners with static IPs](https://docs.github.com/en/actions/using-github-hosted-runners/about-larger-runners).

### Pinning the action version

Pin to a specific release tag (or commit SHA) rather than a branch to prevent
unexpected changes from affecting your builds:

```yaml
# Specific release (recommended)
uses: icedream/sign-with-osslsignserver-action@v1

# Specific commit (most locked-down)
uses: icedream/sign-with-osslsignserver-action@<commit-sha>
```

## Setting up osslsignserver

See the [osslsignserver documentation](https://github.com/icedream/go-osslsignserver)
for server setup. Key configuration relevant to this action:

```yaml
# config.yml (server side)
apiKeyHMACSecret: "/etc/osslsignserver/signing-secret.txt"  # must match api-key-secret input

profiles:
  windows-release:
    certificate:
      type: pkcs11
      key: "pkcs11:slot-id=0;object=code-signing-key"
    timestamper:
      type: rfc3161
      urls:
        - "http://timestamp.digicert.com"
    description: "My App"
    description_url: "https://example.com"
```

Generate a strong signing secret:

```bash
openssl rand -hex 32 > /etc/osslsignserver/signing-secret.txt
chmod 0400 /etc/osslsignserver/signing-secret.txt
```

Then add the same value as a secret in your GitHub repository
(**Settings → Secrets and variables → Actions → New repository secret**).

## Troubleshooting

| Error | Cause | Fix |
|-------|-------|-----|
| HTTP 401, timestamp validation failed | Clock skew between runner and server | Ensure server NTP is in sync; timestamps must be within ±5 minutes |
| HTTP 403, invalid request signature | Wrong `api-key-secret` | Verify the secret matches the server's `apiKeyHMACSecret` file exactly |
| HTTP 404, profile not found | Wrong `profile` name | Check profile names in the server's `config.yml` |
| HTTP 422, signing failed | Signing backend error | Check server logs; token may be locked or certificate expired |
| HTTP 503, concurrent limit reached | Too many concurrent requests | Retry later, or raise `maxConcurrentRequests` on the server |
| curl: (28) Operation timed out | Network or server is slow | Increase `timeout` input |
| `Required tool not found: curl` | Runner lacks curl | Switch to `ubuntu-latest` or install curl first |

## Local development

A mock server is included for testing the action against a real HTTP server
without needing a live osslsignserver instance:

```bash
# Start with HMAC validation enabled
python3 scripts/mock-server.py --port 16973 --secret my-hmac-secret

# Start with signature presence check only (no secret needed)
python3 scripts/mock-server.py --port 16973

# Full option list
python3 scripts/mock-server.py --help
```

The mock server echoes the uploaded file back as the "signed" response,
which is enough to verify the action's request construction end-to-end.
