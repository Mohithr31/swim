#!/usr/bin/env python3
"""
JOCKY Scheduled Database Backup Script

Run directly or via the backup sidecar container.
Retains the last N backups, removing older ones.
Records each backup in a JSON manifest for auditability.
"""
import os, sys, json, glob, logging
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("jocky_backup")

RETAIN = int(os.environ.get("JOCKY_BACKUP_RETAIN", "14"))  # keep last 14 backups

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from server.database import backup_db, list_backups

def main():
    log.info("Starting JOCKY database backup")
    try:
        meta = backup_db()
        log.info("Backup created: %s  SHA-256: %s", meta["backup"], meta["sha256"])
    except Exception as e:
        log.error("Backup FAILED: %s", e)
        sys.exit(1)

    # Prune old backups
    backups = list_backups()
    if len(backups) > RETAIN:
        to_remove = backups[:-RETAIN]
        for b in to_remove:
            try:
                os.remove(b["path"])
                meta_f = b["path"] + ".meta.json"
                if os.path.exists(meta_f):
                    os.remove(meta_f)
                log.info("Pruned old backup: %s", b["path"])
            except Exception as e:
                log.warning("Could not prune %s: %s", b["path"], e)

    log.info("Backup complete. Retained %d backup(s).", min(len(backups), RETAIN))

if __name__ == "__main__":
    main()
