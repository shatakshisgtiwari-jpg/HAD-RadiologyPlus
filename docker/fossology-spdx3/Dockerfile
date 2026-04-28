# SPDX-FileCopyrightText: 2026 Contributors
# SPDX-License-Identifier: MIT

# ── Stage 1: Build C scanner binaries from source ──
FROM debian:bookworm-slim AS builder

WORKDIR /fossology

RUN DEBIAN_FRONTEND=noninteractive apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates git lsb-release sudo cmake ninja-build \
    gcc g++ libxslt1-dev dpkg-dev \
    libmagic-dev libjson-c-dev libglib2.0-dev \
    libboost-regex-dev libicu-dev libssl-dev \
 && rm -rf /var/lib/apt/lists/*

ARG FOSSOLOGY_REPO=https://github.com/shatakshisgtiwari-jpg/fossology.git
ARG FOSSOLOGY_BRANCH=master

RUN git clone --depth 1 --branch ${FOSSOLOGY_BRANCH} ${FOSSOLOGY_REPO} .

RUN cmake -DCMAKE_BUILD_TYPE=MinSizeRel \
    -DAGENTS="nomos;copyright;ojo" \
    -S . -B build -G Ninja \
 && ninja -C build nomossa copyright keyword ojo_exec

RUN dpkg-shlibdeps -Orun-deps \
    -ebuild/src/nomos/agent/nomossa \
    -ebuild/src/copyright/agent/copyright \
    -ebuild/src/copyright/agent/keyword \
    -ebuild/src/ojo/agent/ojo \
 && sed -E -i -e 's/(shlibs:Depends=)|(\(>=?[ 0-9a-z:.~+-]*\))|(,)//ig' run-deps

# ── Stage 2: Minimal runtime image ──
FROM debian:bookworm-slim

LABEL org.opencontainers.image.authors="shatakshisgtiwari-jpg"
LABEL org.opencontainers.image.description="FOSSology SPDX 3.0 scanner"

COPY --from=builder /fossology/run-deps /opt/run-deps

RUN echo 'APT::Install-Recommends "0"; APT::Install-Suggests "0";' \
    >> /etc/apt/apt.conf \
 && DEBIAN_FRONTEND=noninteractive apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    $(cat /opt/run-deps) python3 \
 && DEBIAN_FRONTEND=noninteractive apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/* /opt/run-deps

COPY --from=builder /fossology/build/src/nomos/agent/nomossa /bin/nomossa
COPY --from=builder /fossology/build/src/copyright/agent/copyright /bin/copyright
COPY --from=builder /fossology/build/src/copyright/agent/keyword /bin/keyword
COPY --from=builder /fossology/build/src/ojo/agent/ojo /bin/ojo
COPY --from=builder /fossology/src/nomos/agent/nomossa.conf \
    /usr/local/share/fossology/nomos/agent/nomossa.conf
COPY --from=builder /fossology/src/copyright/agent/copyright.conf \
    /usr/local/share/fossology/copyright/agent/copyright.conf
COPY --from=builder /fossology/src/copyright/agent/keyword.conf \
    /usr/local/share/fossology/keyword/agent/keyword.conf

COPY spdx3_builder.py /opt/spdx3_builder.py
COPY fossology_spdx3_scanner.py /bin/fossologyscanner

ENTRYPOINT ["python3", "/bin/fossologyscanner"]
CMD ["copyright"]
