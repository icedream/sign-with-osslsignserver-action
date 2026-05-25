#!/usr/bin/env python3
"""
mock-server.py — minimal osslsignserver mock for local development and CI testing.

Implements:
  GET  /         → 200 "osslsignserver mock"
  POST /v1/sign  → validates required headers, echoes back the uploaded file

Usage:
  python3 scripts/mock-server.py [--host HOST] [--port PORT] [--secret SECRET]

Options:
  --host    Bind address (default: 127.0.0.1)
  --port    Bind port    (default: 16973)
  --secret  HMAC shared secret to validate request signatures.
            When omitted, signatures are checked for presence but not verified.
"""

import argparse
import hashlib
import hmac
import http.server
import sys
from email import message_from_bytes


def _parse_multipart(content_type: str, body: bytes) -> dict[str, bytes]:
    """Return a dict mapping form field names to their raw bytes."""
    # email.message_from_bytes expects RFC 2822 headers; we fake the top-level
    # Content-Type so it can parse the multipart body for us.
    msg = message_from_bytes(
        f"Content-Type: {content_type}\r\n\r\n".encode() + body
    )
    fields: dict[str, bytes] = {}
    for part in msg.get_payload():
        disposition = part.get("Content-Disposition", "")
        # Extract name= from the disposition header
        name = None
        for segment in disposition.split(";"):
            segment = segment.strip()
            if segment.startswith("name="):
                name = segment[5:].strip('"')
        if name is not None:
            payload = part.get_payload(decode=True)
            if payload is not None:
                fields[name] = payload
    return fields


class Handler(http.server.BaseHTTPRequestHandler):
    secret: bytes | None = None  # set by main()

    def log_message(self, fmt: str, *args) -> None:  # type: ignore[override]
        print(fmt % args, file=sys.stderr, flush=True)

    # ------------------------------------------------------------------
    # GET /
    # ------------------------------------------------------------------
    def do_GET(self) -> None:
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"osslsignserver mock\n")

    # ------------------------------------------------------------------
    # POST /v1/sign
    # ------------------------------------------------------------------
    def do_POST(self) -> None:
        if self.path != "/v1/sign":
            self._error(404, f"not found: {self.path}")
            return

        # ── Required signing headers ──────────────────────────────────
        timestamp = self.headers.get("X-Timestamp")
        request_id = self.headers.get("X-Request-ID")
        signature = self.headers.get("X-Request-Signature")
        for name, value in (
            ("X-Timestamp", timestamp),
            ("X-Request-ID", request_id),
            ("X-Request-Signature", signature),
        ):
            if not value:
                self._error(400, f"missing required header: {name}")
                return

        # ── Read body ────────────────────────────────────────────────
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        content_type = self.headers.get("Content-Type", "")

        try:
            fields = _parse_multipart(content_type, body)
        except Exception as exc:
            self._error(400, f"failed to parse multipart body: {exc}")
            return

        file_data = fields.get("file")
        profile = fields.get("profile", b"").decode()

        if file_data is None:
            self._error(400, "missing form field: file")
            return
        if not profile:
            self._error(400, "missing form field: profile")
            return

        # ── Optional HMAC validation ─────────────────────────────────
        if self.secret is not None:
            file_sha256 = hashlib.sha256(file_data).hexdigest()
            canonical = (
                f"POST\n/v1/sign\n{timestamp}\n{request_id}\n{file_sha256}\n{profile}\n"
            )
            expected = hmac.new(
                self.secret, canonical.encode(), hashlib.sha256
            ).hexdigest()
            if not hmac.compare_digest(signature, expected):
                self._error(403, "invalid request signature")
                return

        # ── Echo the file back as the "signed" artifact ───────────────
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header(
            "Content-Disposition", 'attachment; filename="signed-artifact"'
        )
        self.end_headers()
        self.wfile.write(file_data)

    def _error(self, code: int, message: str) -> None:
        body = f'{{"error": "{message}"}}\n'.encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Minimal osslsignserver mock for local development and CI testing.",
        epilog=(
            "Example:\n"
            "  python3 scripts/mock-server.py --port 16973 --secret my-hmac-secret\n\n"
            "Then point the action at http://127.0.0.1:16973."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=16973,
        help="Bind port (default: 16973)",
    )
    parser.add_argument(
        "--secret",
        default=None,
        help=(
            "HMAC shared secret to validate request signatures. "
            "When omitted, signatures are checked for presence but not verified."
        ),
    )
    args = parser.parse_args()

    Handler.secret = args.secret.encode() if args.secret else None

    server = http.server.HTTPServer((args.host, args.port), Handler)
    validation = (
        f"HMAC validation ON  (secret length: {len(args.secret)} chars)"
        if args.secret
        else "HMAC validation OFF (no --secret provided)"
    )
    print(
        f"osslsignserver mock listening on http://{args.host}:{args.port}/\n"
        f"{validation}\n"
        "Press Ctrl-C to stop.",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.", flush=True)


if __name__ == "__main__":
    main()
