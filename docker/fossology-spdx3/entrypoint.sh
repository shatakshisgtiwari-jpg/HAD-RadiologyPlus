#!/bin/bash

# SPDX-FileCopyrightText: 2026 Contributors
# SPDX-License-Identifier: MIT

# ── Wrapper entrypoint ──
# Preserves the original fossology-action interface:
#   1. Runs /bin/fossologyscanner with ALL original args (pass-through)
#   2. If SPDX3_JSON was requested, additionally generates SPDX 3.0 JSON-LD
#
# Usage from action.yaml args:
#   /bin/fossologyscanner copyright repo --report SPDX3_JSON ...

# ── Step 1: Detect if SPDX3_JSON was requested ──
SPDX3_REQUESTED=false
MODIFIED_ARGS="$*"

if echo "$MODIFIED_ARGS" | grep -qi "SPDX3_JSON"; then
    SPDX3_REQUESTED=true
    # Replace SPDX3_JSON with TEXT for fossologyscanner (it doesn't understand SPDX3)
    MODIFIED_ARGS=$(echo "$MODIFIED_ARGS" | sed 's/SPDX3_JSON/TEXT/gi')
    echo "[SPDX3] SPDX 3.0 JSON-LD report requested — will generate after scan"
    echo "[SPDX3] Running fossologyscanner with TEXT format first"
    echo ""
fi

# ── Step 2: Run original fossologyscanner with all args ──
# This is exactly what upstream fossology-action does
/bin/fossologyscanner $MODIFIED_ARGS || true
SCAN_EXIT=$?

echo ""
echo "[fossologyscanner] Scan completed (exit code: ${SCAN_EXIT})"

# ── Step 3: If SPDX3 requested, generate SPDX 3.0 report ──
if [ "$SPDX3_REQUESTED" = true ]; then
    echo ""
    echo "============================================================"
    echo "  Generating SPDX 3.0 JSON-LD report..."
    echo "============================================================"
    echo ""

    SCAN_DIR="${GITHUB_WORKSPACE:-/github/workspace}"
    OUTPUT_DIR="${SCAN_DIR}/results"
    SPDX3_OUTPUT="${OUTPUT_DIR}/spdx3_report.jsonld"

    mkdir -p "${OUTPUT_DIR}"

    # Run copyright scanner with -J (JSON) to get structured findings,
    # then build SPDX 3.0 from those findings
    python3 /opt/spdx3_scanner.py copyright \
        --scan-dir "${SCAN_DIR}" \
        --output "${SPDX3_OUTPUT}" \
        2>&1

    echo ""
    if [ -f "${SPDX3_OUTPUT}" ]; then
        echo "[SPDX3] Report written: ${SPDX3_OUTPUT}"
        echo "[SPDX3] Size: $(wc -c < "${SPDX3_OUTPUT}") bytes"
    else
        echo "[SPDX3] WARNING: SPDX 3.0 report was not generated"
    fi
fi

echo ""
echo "============================================================"
echo "  Pipeline complete"
echo "============================================================"

exit ${SCAN_EXIT}
