# SPDX-FileCopyrightText: 2026 Contributors
# SPDX-License-Identifier: MIT

# ── Base: official FOSSology scanner image ──
# Contains /bin/fossologyscanner, nomos, ojo, copyright, keyword
# and the full CLI interface (scan_mode, report_format, allowlist, etc.)
FROM fossology/fossology:scanner

LABEL org.opencontainers.image.authors="shatakshisgtiwari-jpg"
LABEL org.opencontainers.image.description="FOSSology scanner + SPDX 3.0 report builder"

# Ensure pip is available, then install spdx-tools for SPDX 3.0
# --break-system-packages is needed on Debian Bookworm (PEP 668) inside Docker
RUN pip3 install --no-cache-dir --break-system-packages spdx-tools

# SPDX 3.0 builder + scanner
COPY spdx3_builder.py /opt/spdx3_builder.py
COPY fossology_spdx3_scanner.py /opt/spdx3_scanner.py

# Wrapper entrypoint: runs copyright scanner → SPDX 3.0 report
COPY entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh

ENTRYPOINT ["/opt/entrypoint.sh"]
