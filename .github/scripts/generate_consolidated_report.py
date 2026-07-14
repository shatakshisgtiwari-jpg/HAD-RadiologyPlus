# -------------------------------------------------------------------------------
# SPDX-License-Identifier: MIT
# -------------------------------------------------------------------------------
"""Generate consolidated SPDX report from CycloneDX SBOM.

Reads a CycloneDX SBOM and produces a consolidated SPDX 2.3 report
covering all components. This serves as a fallback when the FOSSology
Docker scanner is not available on the CI runner.

Usage:
    python generate_consolidated_report.py

Environment:
    SBOM_PATH  - Path to input SBOM (default: created-sbom.json)
    OUTPUT_DIR - Output directory (default: results)
"""

import json
import os
import sys
from datetime import datetime, timezone


def main() -> None:
    sbom_path = os.environ.get("SBOM_PATH", "created-sbom.json")
    output_dir = os.environ.get("OUTPUT_DIR", "results")

    if not os.path.exists(sbom_path):
        print(f"ERROR: SBOM not found at {sbom_path}")
        sys.exit(1)

    with open(sbom_path, "r") as f:
        sbom = json.load(f)

    # Build consolidated SPDX report
    spdx_report = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": "FOSSology Scan Report - had-radiologyplus",
        "documentNamespace": (
            "https://spdx.org/spdxdocs/fossology-scan-"
            + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        ),
        "creationInfo": {
            "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "creators": ["Tool: FOSSology-Scanner-Fallback"],
        },
        "packages": [],
        "files": [],
        "relationships": [],
    }

    # Components to skip (GitHub Actions, not real dependencies)
    skip_names = {
        "checkout",
        "download-artifact",
        "setup-java",
        "setup-node",
        "setup-python",
        "upload-artifact",
    }

    components = sbom.get("components", [])
    print(f"Processing {len(components)} components from SBOM...")

    for comp in components:
        name = comp.get("name", "unknown")
        version = comp.get("version", "unknown")
        purl = comp.get("purl", "")

        if name in skip_names:
            continue

        safe_name = name.replace(" ", "-").replace("/", "-").replace("@", "-")
        pkg = {
            "SPDXID": f"SPDXRef-Package-{safe_name}",
            "name": name,
            "versionInfo": version,
            "downloadLocation": "NOASSERTION",
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
        }

        if purl:
            pkg["externalRefs"] = [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": purl,
                }
            ]

        spdx_report["packages"].append(pkg)
        spdx_report["relationships"].append(
            {
                "spdxElementId": "SPDXRef-DOCUMENT",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": pkg["SPDXID"],
            }
        )

    # Write consolidated report
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, "sbom_spdx.json")
    with open(output_path, "w") as f:
        json.dump(spdx_report, f, indent=2)

    pkg_count = len(spdx_report["packages"])
    print(f"Generated consolidated SPDX report with {pkg_count} packages")
    print(f"Output: {output_path}")
    print(f"File size: {os.path.getsize(output_path)} bytes")


if __name__ == "__main__":
    main()
