# Forensic Preview & Process Inspection Upgrade

## File previews
- PDF artifacts render in an embedded read-only PDF viewer instead of raw `%PDF` bytes.
- Images render as image previews.
- DOCX previews extract document text from `word/document.xml` in memory.
- Common text/code/data files render as readable text.
- Archive members in ZIP/TAR/GZ can be selected and previewed without extracting or modifying the archive.
- Archive images render as images and archive PDFs render in the embedded PDF viewer.

## Process forensics
Linux process telemetry now includes:
- PID / PPID and parent process name
- Child process list and child count
- Executable path and cached SHA-256
- Command line
- CPU percentage (sampled between telemetry cycles)
- RSS / VM size / memory percentage
- Process state and thread count
- Start time
- Working directory and process root
- Open file descriptors / paths
- `/proc/<pid>/maps` read-only memory mappings

All collection remains read-only. Memory pages are not modified and archive members are not extracted to disk by the preview feature.
