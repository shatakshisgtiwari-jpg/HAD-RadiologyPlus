# SPDX-FileCopyrightText: 2026 Contributors
# SPDX-License-Identifier: MIT

# ──────────────────────────────────────────────────────────────────
# FOSSology SPDX 3.0 Scanner
#
# Extends the official fossology/fossology:scanner image by replacing
# the reporting pipeline. The C scanner binaries (nomossa, copyright,
# ojo, keyword) are unchanged. The Python entrypoint is replaced with
# our modified version that produces SPDX 3.0 JSON-LD directly from
# scanner result objects — no SPDX 2.x at any stage.
#
# Build (from repo root):
#   docker build -f docker/fossology-spdx3/Dockerfile \
#     -t ghcr.io/<owner>/<repo>/fossology-spdx3:latest .
# ──────────────────────────────────────────────────────────────────

FROM fossology/fossology:scanner

# Copy SPDX 3.0 builder library
COPY scripts/spdx3_builder.py /opt/spdx3_builder.py

# Replace the default fossologyscanner.py with our SPDX 3.0 version.
# This is the key modification: the scanner now produces SPDX 3.0
# directly from scanner objects, bypassing the SPDX 2.x reporting.
COPY docker/fossology-spdx3/fossology_spdx3_scanner.py /bin/fossologyscanner

WORKDIR /opt/repo

ENTRYPOINT ["python3", "/bin/fossologyscanner"]
CMD ["copyright", "repo"]
