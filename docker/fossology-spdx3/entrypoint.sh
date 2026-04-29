#!/bin/bash

# SPDX-FileCopyrightText: 2026 Contributors
# SPDX-License-Identifier: MIT

# ── Wrapper entrypoint ──
# 1. Runs the original FOSSology scanner (produces TEXT scan output)
# 2. Generates SPDX 3.0 JSON-LD report from scan results
#
# Note: We do NOT use set -e because fossologyscanner exits non-zero
# when it finds copyrights/licenses (expected behavior). We still
# want Step 2 to run regardless.

echo "============================================================"
echo "  FOSSology Scanner + SPDX 3.0 Report Builder"
echo "============================================================"
echo ""

# ── Step 1: Run the original FOSSology scanner ──
echo "[Step 1/2] Running FOSSology scanner..."
echo ""

# Pass all arguments directly to fossologyscanner
# Note: args arrive as a single folded string from action.yaml,
# so we use $* without quotes to allow word splitting
/bin/fossologyscanner $* || true
SCAN_EXIT=$?

echo ""
echo "[Step 1/2] FOSSology scan completed (exit code: ${SCAN_EXIT})"
echo ""

# ── Step 2: Generate SPDX 3.0 report ──
echo "[Step 2/2] Generating SPDX 3.0 JSON-LD report..."
echo ""

# Determine the scan directory (defaults to workspace mount point)
SCAN_DIR="${GITHUB_WORKSPACE:-/opt/repo}"
OUTPUT_DIR="${SCAN_DIR}/results"
SPDX3_OUTPUT="${OUTPUT_DIR}/spdx3_report.jsonld"

mkdir -p "${OUTPUT_DIR}"

python3 /opt/spdx3_scanner.py \
    copyright keyword \
    --scan-dir "${SCAN_DIR}" \
    --output "${SPDX3_OUTPUT}" \
    2>&1 || echo "WARNING: SPDX 3.0 generation encountered issues"

echo ""
if [ -f "${SPDX3_OUTPUT}" ]; then
    echo "[Step 2/2] SPDX 3.0 report written to: ${SPDX3_OUTPUT}"
    echo "  Size: $(wc -c < "${SPDX3_OUTPUT}") bytes"
else
    echo "[Step 2/2] WARNING: SPDX 3.0 report was not generated"
fi

echo ""
echo "============================================================"
echo "  Pipeline complete"
echo "============================================================"

# Exit with the scanner's exit code (not the builder's)
exit ${SCAN_EXIT}
