"""
TINY MONITOR — Server Entrypoint
Launches the canonical Tiny Monitor platform.
"""

import os
import sys

root_dir = os.path.dirname(os.path.abspath(__file__))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(root_dir, ".env"))
except Exception:
    pass

from server.server import app, init_db, get_db_path, get_evidence_dir, get_server_api_key
from server.tinyfish_service import is_tinyfish_configured, get_tinyfish_api_key

if __name__ == "__main__":
    host = os.environ.get("JOCKY_HOST", os.environ.get("HOST", "127.0.0.1"))
    port = int(os.environ.get("JOCKY_PORT", os.environ.get("PORT", "5000")))
    debug = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true")

    db_path = get_db_path()
    init_db(db_path)

    api_key_configured = bool(get_server_api_key())
    tf_configured = is_tinyfish_configured()

    print("=" * 70)
    print("   T I N Y   M O N I T O R   P L A T F O R M")
    print("   Canonical Tiny Monitor Platform")
    print("   Swim with TinyFish Hackathon — Presidency University, Bengaluru")
    print("=" * 70)
    print(f" * Server running on: http://{host}:{port}/")
    print(f" * Database: {db_path}")
    print(f" * Evidence Storage: {get_evidence_dir()}")
    print(f" * Agent API Authentication: {'ENFORCED' if api_key_configured else 'DEV_OPEN'}")
    print(f" * TinyFish Threat Intel: {'CONFIGURED & VERIFIED' if tf_configured else 'NOT CONFIGURED'}")
    print("=" * 70)

    app.run(host=host, port=port, debug=debug)

