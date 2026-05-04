#!/bin/bash

# SPDX-FileCopyrightText: 2026 Contributors
# SPDX-License-Identifier: MIT

# ── Single-pipeline entrypoint ──
# Runs FOSSology agents ONCE, collects JSON findings, and builds:
#   1. Text report (scan_report.txt)
#   2. SPDX 3.0 JSON-LD report
#
# Agents are run directly (/bin/nomossa, /bin/ojo, /bin/copyright, /bin/keyword)
# with -J flag for structured JSON output. No redundant double-scanning.

set -euo pipefail

SCAN_DIR="${GITHUB_WORKSPACE:-/github/workspace}"
OUTPUT_DIR="${SCAN_DIR}/results"
SPDX3_OUTPUT="${OUTPUT_DIR}/spdx3_report.jsonld"

mkdir -p "${OUTPUT_DIR}"

# ── Parse arguments to extract scanner names and allowlist ──
ALL_ARGS="$*"
DETECTED_SCANNERS=""
ALLOWLIST_PATH=""

for word in $ALL_ARGS; do
    case "$word" in
        nomos|ojo|copyright|keyword)
            DETECTED_SCANNERS="$DETECTED_SCANNERS $word"
            ;;
    esac
done

# Check for allowlist file path in environment or common locations
if [ -n "${INPUT_ALLOWLIST_FILE_PATH:-}" ]; then
    ALLOWLIST_PATH="${SCAN_DIR}/${INPUT_ALLOWLIST_FILE_PATH}"
elif [ -f "${SCAN_DIR}/allowlist.json" ]; then
    ALLOWLIST_PATH="${SCAN_DIR}/allowlist.json"
fi

DETECTED_SCANNERS=$(echo "$DETECTED_SCANNERS" | xargs)
if [ -z "$DETECTED_SCANNERS" ]; then
    DETECTED_SCANNERS="copyright"
fi

echo "============================================================"
echo "  FOSSology SPDX 3.0 Pipeline"
echo "============================================================"
echo ""
echo "  Scan directory: ${SCAN_DIR}"
echo "  Scanners:       ${DETECTED_SCANNERS}"
echo "  Allowlist:      ${ALLOWLIST_PATH:-none}"
echo "  Output:         ${SPDX3_OUTPUT}"
echo ""

# ── Single pipeline: agents → findings → SPDX 3.0 ──
# The Python scanner runs each agent binary once with -J (JSON output),
# collects all findings, applies allowlist filtering, and builds the report.

ALLOWLIST_ARG=""
if [ -n "$ALLOWLIST_PATH" ] && [ -f "$ALLOWLIST_PATH" ]; then
    ALLOWLIST_ARG="--allowlist ${ALLOWLIST_PATH}"
fi

python3 /opt/spdx3_scanner.py $DETECTED_SCANNERS \
    --scan-dir "${SCAN_DIR}" \
    --output "${SPDX3_OUTPUT}" \
    $ALLOWLIST_ARG \
    2>&1

SCAN_EXIT=$?

echo ""
if [ -f "${SPDX3_OUTPUT}" ]; then
    echo "[SPDX3] Report written: ${SPDX3_OUTPUT}"
    echo "[SPDX3] Size: $(wc -c < "${SPDX3_OUTPUT}") bytes"
else
    echo "[SPDX3] WARNING: SPDX 3.0 report was not generated"
fi

echo ""
echo "============================================================"
echo "  Pipeline complete"
echo "============================================================"

exit ${SCAN_EXIT}
