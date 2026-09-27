# Three forensic bug fixes

1. Email collection is endpoint-agent initiated via a bounded request queue; server-host rescanning is not used for an enrolled endpoint.
2. Linux deleted-file scan falls back to explicitly labeled Trash/temp artifacts when ext4 debugfs recovery is unavailable.
3. File metadata resolves the selected device before locality checks and exposes SHA-256 plus EXIF GPS metadata for supported image files.
