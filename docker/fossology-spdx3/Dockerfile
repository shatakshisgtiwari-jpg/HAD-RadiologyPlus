# SPDX-FileCopyrightText: 2026 Contributors
# SPDX-License-Identifier: MIT

FROM fossology/fossology:scanner

COPY scripts/spdx3_builder.py /opt/spdx3_builder.py

COPY docker/fossology-spdx3/fossology_spdx3_scanner.py /bin/fossologyscanner

WORKDIR /opt/repo

ENTRYPOINT ["python3", "/bin/fossologyscanner"]
CMD ["copyright"]
