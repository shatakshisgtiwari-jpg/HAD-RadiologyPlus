#!/bin/bash

# SPDX-FileCopyrightText: 2026 Contributors
# SPDX-License-Identifier: MIT

# ── Wrapper entrypoint ──
# Runs /bin/copyright -J directly to get structured JSON findings,
# then feeds them into spdx3_builder to produce SPDX 3.0 JSON-LD.
#
# No fossologyscanner binary is used — we call the C scanner directly
# so we get machine-readable output with zero SPDX 2 involvement.

echo "============================================================"
echo "  FOSSology Copyright Scanner → SPDX 3.0 Report Builder"
echo "============================================================"
echo ""

SCAN_DIR="${GITHUB_WORKSPACE:-/opt/repo}"
OUTPUT_DIR="${SCAN_DIR}/results"
SPDX3_OUTPUT="${OUTPUT_DIR}/spdx3_report.jsonld"

mkdir -p "${OUTPUT_DIR}"

echo "Scan directory: ${SCAN_DIR}"
echo "Output:         ${SPDX3_OUTPUT}"
echo ""

# Single step: run copyright scanner → collect findings → SPDX 3.0 JSON-LD
python3 /opt/spdx3_scanner.py copyright \
    --scan-dir "${SCAN_DIR}" \
    --output "${SPDX3_OUTPUT}" \
    2>&1
SCAN_EXIT=$?

echo ""
if [ -f "${SPDX3_OUTPUT}" ]; then
    echo "SPDX 3.0 report: ${SPDX3_OUTPUT}"
    echo "Size: $(wc -c < "${SPDX3_OUTPUT}") bytes"
else
    echo "WARNING: SPDX 3.0 report was not generated"
fi

echo ""
echo "============================================================"
echo "  Pipeline complete (exit code: ${SCAN_EXIT})"
echo "============================================================"

exit ${SCAN_EXIT}
