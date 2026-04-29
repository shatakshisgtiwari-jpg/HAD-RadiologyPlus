#!/bin/bash

# SPDX-FileCopyrightText: 2026 Contributors
# SPDX-License-Identifier: MIT

# ── Wrapper entrypoint ──
# 1. Runs the original FOSSology scanner (TEXT output to stdout)
# 2. Dumps raw copyright findings as JSON
# 3. Generates SPDX 3.0 JSON-LD report
#
# Note: We do NOT use set -e because fossologyscanner exits non-zero
# when it finds copyrights/licenses (expected behavior). We still
# want subsequent steps to run regardless.

echo "============================================================"
echo "  FOSSology Scanner + SPDX 3.0 Report Builder"
echo "============================================================"
echo ""

# Determine the scan directory (defaults to workspace mount point)
SCAN_DIR="${GITHUB_WORKSPACE:-/opt/repo}"
OUTPUT_DIR="${SCAN_DIR}/results"
mkdir -p "${OUTPUT_DIR}"

# ── Step 1: Run the original FOSSology scanner (TEXT to stdout) ──
echo "[Step 1/3] Running FOSSology scanner..."
echo ""

/bin/fossologyscanner $* || true
SCAN_EXIT=$?

echo ""
echo "[Step 1/3] FOSSology scan completed (exit code: ${SCAN_EXIT})"
echo ""

# ── Step 2: Dump raw copyright agent output as JSON ──
echo "[Step 2/3] Generating raw copyright JSON..."
echo ""

/bin/copyright -J -d "${SCAN_DIR}" > "${OUTPUT_DIR}/copyright.json" 2>/dev/null || true

if [ -f "${OUTPUT_DIR}/copyright.json" ]; then
    echo "[Step 2/3] Raw copyright JSON written to: ${OUTPUT_DIR}/copyright.json"
    echo "  Size: $(wc -c < "${OUTPUT_DIR}/copyright.json") bytes"
else
    echo "[Step 2/3] WARNING: copyright JSON was not generated"
fi
echo ""

# ── Step 3: Generate SPDX 3.0 report ──
echo "[Step 3/3] Generating SPDX 3.0 JSON-LD report..."
echo ""

SPDX3_OUTPUT="${OUTPUT_DIR}/spdx3_report.jsonld"

python3 -c "
import sys
sys.path.insert(0, '/opt')
import spdx3_builder
spdx3_builder.build(
    repo_root='${SCAN_DIR}',
    report_dir=None,
    output_path='${SPDX3_OUTPUT}',
)
" 2>&1 || echo "WARNING: SPDX 3.0 generation encountered issues"

echo ""
if [ -f "${SPDX3_OUTPUT}" ]; then
    echo "[Step 3/3] SPDX 3.0 report written to: ${SPDX3_OUTPUT}"
    echo "  Size: $(wc -c < "${SPDX3_OUTPUT}") bytes"
else
    echo "[Step 3/3] WARNING: SPDX 3.0 report was not generated"
fi

echo ""
echo "============================================================"
echo "  Pipeline complete"
echo "============================================================"
echo "  Artifacts in ${OUTPUT_DIR}/:"
echo "    - copyright.json     (raw copyright agent JSON)"
echo "    - spdx3_report.jsonld (SPDX 3.0 JSON-LD)"
echo "============================================================"

# Exit with the scanner's exit code (not the builder's)
exit ${SCAN_EXIT}
