#!/usr/bin/env bash
# JOCKY Forensic Collection Execution Script Wrapper
set -e

CASE_ID="${1:-}"
SESSION_ID="${2:-}"
JOB_ID="${3:-}"
OUTPUT_DIR="${4:-./evidence}"

echo "[JOCKY-COLLECT] Starting collection for ${CASE_ID}/${SESSION_ID}/${JOB_ID}..."
mkdir -p "${OUTPUT_DIR}/${CASE_ID}/${SESSION_ID}/${JOB_ID}"

python3 -m agent.jocky_agent --case-id "${CASE_ID}" --session-id "${SESSION_ID}" --job-id "${JOB_ID}" --out "${OUTPUT_DIR}"
echo "[JOCKY-COLLECT] Collection complete."
