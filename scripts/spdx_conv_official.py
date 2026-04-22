#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 HAD-RadiologyPlus Contributors
# SPDX-License-Identifier: MIT

"""
SPDX 2.3 JSON → SPDX 3.0 JSON-LD Converter (using official spdx-tools library)

Uses the spdx-tools library's built-in bump_spdx_document() to convert
FOSSology CI scanner SPDX 2.3 JSON reports to SPDX 3.0 JSON-LD format.

Usage:
    pip install spdx-tools==0.8.5
    python spdx_conv_official.py <input_spdx2.json> <output_spdx3.jsonld>
"""

import sys

from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx3.bump_from_spdx2.spdx_document import bump_spdx_document
from spdx_tools.spdx3.writer.json_ld.json_ld_writer import write_payload


def convert(input_path: str, output_path: str) -> None:
    """Convert SPDX 2.3 JSON to SPDX 3.0 JSON-LD using official spdx-tools."""

    # Step 1: Parse the SPDX 2.3 document
    print(f"[1/3] Parsing SPDX 2.3 document: {input_path}")
    document = parse_file(input_path)
    print(f"      Name: {document.creation_info.name}")
    print(f"      Version: {document.creation_info.spdx_version}")
    print(f"      Packages: {len(document.packages)}")
    print(f"      Files: {len(document.files)}")
    print(f"      Relationships: {len(document.relationships)}")

    # Step 2: Bump (convert) to SPDX 3.0 Payload
    print("[2/3] Converting to SPDX 3.0 via bump_spdx_document()...")
    payload = bump_spdx_document(document)
    print(f"      Payload elements: {len(payload.get_full_map())}")

    # Step 3: Write the SPDX 3.0 JSON-LD file
    #   spdx-tools appends .jsonld automatically, so strip it if already present
    write_path = output_path
    if output_path.endswith('.jsonld'):
        write_path = output_path[:-len('.jsonld')]
    print(f"[3/3] Writing SPDX 3.0 JSON-LD to: {output_path}")
    write_payload(payload, write_path)

    print("\n── Conversion complete (spdx-tools library) ──")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python spdx_conv_official.py <input_spdx2.json> <output_spdx3.jsonld>")
        sys.exit(1)

    convert(sys.argv[1], sys.argv[2])
