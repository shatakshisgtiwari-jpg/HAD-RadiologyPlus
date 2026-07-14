# -------------------------------------------------------------------------------
# SPDX-License-Identifier: MIT
# -------------------------------------------------------------------------------
"""Generate per-dependency SPDX reports from consolidated report.

Splits a consolidated SPDX report into individual per-dependency reports,
one file per component. Filenames use the format:
    {safe_name}@{safe_version}.spdx.json

This matches what CapyCLI expects when uploading reports to SW360.

Usage:
    python generate_per_dependency_reports.py

Environment:
    REPORT_DIR - Output directory (default: per-dependency-reports)
"""

import json
import os
import re
import sys


def main() -> None:
    consolidated_path = "results/sbom_spdx.json"
    if not os.path.exists(consolidated_path):
        print(f"ERROR: Consolidated report not found at {consolidated_path}")
        sys.exit(1)

    with open(consolidated_path, "r") as f:
        consolidated = json.load(f)

    sbom_path = "created-sbom.json"
    if not os.path.exists(sbom_path):
        print(f"ERROR: SBOM not found at {sbom_path}")
        sys.exit(1)

    with open(sbom_path, "r") as f:
        sbom = json.load(f)

    report_dir = os.environ.get("REPORT_DIR", "per-dependency-reports")
    os.makedirs(report_dir, exist_ok=True)

    # Build a map of component names to versions from SBOM
    sbom_components: dict[str, str] = {}
    for comp in sbom.get("components", []):
        name = comp.get("name", "")
        version = comp.get("version", "unknown")
        sbom_components[name] = version

    # Generate per-dependency report for each package
    packages = consolidated.get("packages", [])
    print(f"Generating reports for {len(packages)} packages...")

    generated = 0
    for pkg in packages:
        name = pkg.get("name", "unknown")
        version = pkg.get("versionInfo", "unknown")

        # Skip if not in SBOM (e.g., GitHub actions)
        if name not in sbom_components:
            continue

        # Sanitize filename (replace special chars with underscores)
        safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", name)
        safe_version = re.sub(r"[^a-zA-Z0-9._-]", "_", version)

        # Use @ separator to match CapyCLI's expected format
        filename = f"{safe_name}@{safe_version}.spdx.json"
        output_path = os.path.join(report_dir, filename)

        # Create per-dependency report
        dep_report = {
            "spdxVersion": consolidated.get("spdxVersion", "SPDX-2.3"),
            "dataLicense": consolidated.get("dataLicense", "CC0-1.0"),
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": f"Per-Dependency Report: {name}",
            "documentNamespace": (
                consolidated.get("documentNamespace", "") + "-" + safe_name
            ),
            "creationInfo": consolidated.get("creationInfo", {}),
            "packages": [pkg],
            "files": [],
            "relationships": [
                r
                for r in consolidated.get("relationships", [])
                if pkg.get("SPDXID", "") in r.get("relatedSpdxElement", "")
            ],
        }

        with open(output_path, "w") as f:
            json.dump(dep_report, f, indent=2)

        generated += 1
        print(f"  Generated: {filename}")

    print(f"Generated {generated} per-dependency reports in {report_dir}/")


if __name__ == "__main__":
    main()
