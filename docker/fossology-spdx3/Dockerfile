# SPDX-FileCopyrightText: 2026 Contributors
# SPDX-License-Identifier: MIT

# ──────────────────────────────────────────────────────────────────
# FOSSology SPDX 3.0 Scanner
#
# Extends the official fossology/fossology:scanner image by replacing
# the reporting pipeline. The C scanner binaries (nomossa, copyright,
# ojo, keyword) are unchanged. The Python entrypoint calls them
# directly via subprocess (-J for JSON output), collects findings,
# and produces SPDX 3.0 JSON-LD. No FoScanner library dependency.
#
# Build (from repo root):
#   docker build -f docker/fossology-spdx3/Dockerfile \
#     -t ghcr.io/<owner>/fossology-spdx3:latest .
# ──────────────────────────────────────────────────────────────────

FROM fossology/fossology:scanner

# Copy SPDX 3.0 builder library
COPY scripts/spdx3_builder.py /opt/spdx3_builder.py

# Replace the default fossologyscanner with our direct-subprocess version.
# This script calls /bin/copyright, /bin/nomossa, /bin/ojo, /bin/keyword
# directly — no FoScanner library needed.
COPY docker/fossology-spdx3/fossology_spdx3_scanner.py /bin/fossologyscanner

WORKDIR /opt/repo

ENTRYPOINT ["python3", "/bin/fossologyscanner"]
CMD ["copyright"]
