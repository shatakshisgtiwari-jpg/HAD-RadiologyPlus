#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Contributors
# SPDX-License-Identifier: MIT

"""SPDX 3.0 Report Builder -- generates JSON-LD from FOSSology agent findings."""

import json
import os
import re
import uuid
from datetime import datetime, timezone


# ═════════════════════════════════════════════════════════════════════
# SPDX 3.0 JSON-LD Context 
# ═════════════════════════════════════════════════════════════════════

_SPDX_NS = "https://spdx.org/rdf/3.0.0/terms"

SPDX_CONTEXT = [
    "https://spdx.org/rdf/3.0.0/spdx-context.jsonld",
    {
        "CreationInfo": f"{_SPDX_NS}/Core/CreationInfo",
        "SpdxDocument": f"{_SPDX_NS}/Core/SpdxDocument",
        "Organization": f"{_SPDX_NS}/Core/Organization",
        "Person": f"{_SPDX_NS}/Core/Person",
        "Tool": f"{_SPDX_NS}/Core/Tool",
        "Relationship": f"{_SPDX_NS}/Core/Relationship",
        "Hash": f"{_SPDX_NS}/Core/Hash",
        "ExternalIdentifier": f"{_SPDX_NS}/Core/ExternalIdentifier",
        "ExternalRef": f"{_SPDX_NS}/Core/ExternalRef",
        "Annotation": f"{_SPDX_NS}/Core/Annotation",
        "software_Package": f"{_SPDX_NS}/Software/Package",
        "software_File": f"{_SPDX_NS}/Software/File",
        "simplelicensing_SimpleLicensingText": f"{_SPDX_NS}/SimpleLicensing/SimpleLicensingText",
        "simplelicensing_LicenseExpression": f"{_SPDX_NS}/SimpleLicensing/LicenseExpression",
        "spdxId": "@id",
        "creationInfo": {"@id": f"{_SPDX_NS}/Core/creationInfo", "@type": "@id"},
        "specVersion": {"@id": f"{_SPDX_NS}/Core/specVersion", "@type": "http://www.w3.org/2001/XMLSchema#string"},
        "created": {"@id": f"{_SPDX_NS}/Core/created", "@type": "http://www.w3.org/2001/XMLSchema#dateTimeStamp"},
        "createdBy": {"@id": f"{_SPDX_NS}/Core/createdBy", "@type": "@id"},
        "createdUsing": {"@id": f"{_SPDX_NS}/Core/createdUsing", "@type": "@id"},
        "name": {"@id": f"{_SPDX_NS}/Core/name", "@type": "http://www.w3.org/2001/XMLSchema#string"},
        "comment": {"@id": f"{_SPDX_NS}/Core/comment", "@type": "http://www.w3.org/2001/XMLSchema#string"},
        "element": {"@id": f"{_SPDX_NS}/Core/element", "@type": "@id"},
        "rootElement": {"@id": f"{_SPDX_NS}/Core/rootElement", "@type": "@id"},
        "profileConformance": {
            "@id": f"{_SPDX_NS}/Core/profileConformance", "@type": "@vocab",
            "@context": {"@vocab": f"{_SPDX_NS}/Core/ProfileIdentifierType/"}
        },
        "dataLicense": {"@id": f"{_SPDX_NS}/Core/dataLicense", "@type": "@id"},
        "from": {"@id": f"{_SPDX_NS}/Core/from", "@type": "@id"},
        "to": {"@id": f"{_SPDX_NS}/Core/to", "@type": "@id"},
        "relationshipType": {
            "@id": f"{_SPDX_NS}/Core/relationshipType", "@type": "@vocab",
            "@context": {"@vocab": f"{_SPDX_NS}/Core/RelationshipType/"}
        },
        "algorithm": {
            "@id": f"{_SPDX_NS}/Core/algorithm", "@type": "@vocab",
            "@context": {"@vocab": f"{_SPDX_NS}/Core/HashAlgorithm/"}
        },
        "hashValue": {"@id": f"{_SPDX_NS}/Core/hashValue", "@type": "http://www.w3.org/2001/XMLSchema#string"},
        "verifiedUsing": {"@id": f"{_SPDX_NS}/Core/verifiedUsing", "@type": "@id"},
        "externalIdentifier": {"@id": f"{_SPDX_NS}/Core/externalIdentifier", "@type": "@id"},
        "externalIdentifierType": {
            "@id": f"{_SPDX_NS}/Core/externalIdentifierType", "@type": "@vocab",
            "@context": {"@vocab": f"{_SPDX_NS}/Core/ExternalIdentifierType/"}
        },
        "identifier": {"@id": f"{_SPDX_NS}/Core/identifier", "@type": "http://www.w3.org/2001/XMLSchema#string"},
        "originatedBy": {"@id": f"{_SPDX_NS}/Core/originatedBy", "@type": "@id"},
        "releaseTime": {"@id": f"{_SPDX_NS}/Core/releaseTime", "@type": "http://www.w3.org/2001/XMLSchema#dateTimeStamp"},
        "annotationType": {
            "@id": f"{_SPDX_NS}/Core/annotationType", "@type": "@vocab",
            "@context": {"@vocab": f"{_SPDX_NS}/Core/AnnotationType/"}
        },
        "subject": {"@id": f"{_SPDX_NS}/Core/subject", "@type": "@id"},
        "statement": {"@id": f"{_SPDX_NS}/Core/statement", "@type": "http://www.w3.org/2001/XMLSchema#string"},
        "software_downloadLocation": {"@id": f"{_SPDX_NS}/Software/downloadLocation", "@type": "http://www.w3.org/2001/XMLSchema#anyURI"},
        "software_packageVersion": {"@id": f"{_SPDX_NS}/Software/packageVersion", "@type": "http://www.w3.org/2001/XMLSchema#string"},
        "software_copyrightText": {"@id": f"{_SPDX_NS}/Software/copyrightText", "@type": "http://www.w3.org/2001/XMLSchema#string"},
        "software_primaryPurpose": {
            "@id": f"{_SPDX_NS}/Software/primaryPurpose", "@type": "@vocab",
            "@context": {"@vocab": f"{_SPDX_NS}/Software/SoftwarePurpose/"}
        },
        "software_homePage": {"@id": f"{_SPDX_NS}/Software/homePage", "@type": "http://www.w3.org/2001/XMLSchema#anyURI"},
        "software_contentType": {"@id": f"{_SPDX_NS}/Software/contentType", "@type": "http://www.w3.org/2001/XMLSchema#string"},
        "suppliedBy": {"@id": f"{_SPDX_NS}/Core/suppliedBy", "@type": "@id"},
        "simplelicensing_licenseText": {"@id": f"{_SPDX_NS}/SimpleLicensing/licenseText", "@type": "http://www.w3.org/2001/XMLSchema#string"},
        "simplelicensing_licenseExpression": {"@id": f"{_SPDX_NS}/SimpleLicensing/licenseExpression", "@type": "http://www.w3.org/2001/XMLSchema#string"},
        "simplelicensing_licenseListVersion": {"@id": f"{_SPDX_NS}/SimpleLicensing/licenseListVersion", "@type": "http://www.w3.org/2001/XMLSchema#string"},
    }
]


# ═════════════════════════════════════════════════════════════════════
# Validation Constants
# ═════════════════════════════════════════════════════════════════════

VALID_TYPES = {
    "CreationInfo", "SpdxDocument", "Organization", "Person", "Tool",
    "Relationship", "Hash", "ExternalIdentifier", "Annotation",
    "software_Package", "software_File",
    "simplelicensing_SimpleLicensingText", "simplelicensing_LicenseExpression",
}

REQUIRED_FIELDS = {
    "CreationInfo": ["specVersion", "created", "createdBy"],
    "SpdxDocument": ["@id", "creationInfo", "name", "element", "rootElement"],
    "Organization": ["@id", "creationInfo", "name"],
    "Person": ["@id", "creationInfo", "name"],
    "Tool": ["@id", "creationInfo", "name"],
    "Relationship": ["@id", "creationInfo", "from", "to", "relationshipType"],
    "Hash": ["algorithm", "hashValue"],
    "software_Package": ["@id", "creationInfo", "name"],
    "software_File": ["@id", "creationInfo", "name"],
    "Annotation": ["@id", "creationInfo", "annotationType", "subject", "statement"],
    "simplelicensing_SimpleLicensingText": ["@id", "creationInfo", "simplelicensing_licenseText"],
    "simplelicensing_LicenseExpression": ["@id", "creationInfo", "simplelicensing_licenseExpression"],
}

VALID_RELATIONSHIP_TYPES = {
    "describes", "describedBy", "contains", "containedBy",
    "dependsOn", "dependencyOf", "generates", "generatedFrom",
    "hasDeclaredLicense", "hasConcludedLicense", "other",
}

VALID_HASH_ALGORITHMS = {"md5", "sha1", "sha256", "sha384", "sha512", "sha3_256"}

VALID_PURPOSES = {"source", "executable", "archive", "application", "documentation", "data", "library", "file", "other"}


# ═════════════════════════════════════════════════════════════════════
# Build SPDX 3.0 Elements
# ═════════════════════════════════════════════════════════════════════

def generate_base_uri(doc_name: str) -> str:
    """Generate a unique URN base URI for element identifiers."""
    unique_id = uuid.uuid4().hex[:12]
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "-", doc_name)
    return f"urn:spdx:{safe_name}/{unique_id}"


def build_creation_info(base_uri: str) -> tuple[dict, list[dict]]:
    """Build CreationInfo + Agent/Tool elements from CI environment.

    Reads env vars: GITHUB_REPOSITORY_OWNER, GITHUB_REPOSITORY, etc.
    Falls back to generic values if not in CI.
    """
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    agents = []
    created_by_ids = []
    created_using_ids = []

    # Organization agent (from CI env or fallback)
    org_name = os.environ.get("GITHUB_REPOSITORY_OWNER", "Unknown")
    org_id = f"{base_uri}/Agent/Organization/{re.sub(r'[^a-zA-Z0-9]', '', org_name)}"
    agents.append({
        "@type": "Organization",
        "@id": org_id,
        "creationInfo": "_:creationinfo",
        "name": org_name,
    })
    created_by_ids.append(org_id)

    # Tool agents
    tools = [
        ("FOSSology CI Scanner", "fossology-ci-scanner"),
        ("spdx3-builder", "spdx3-builder"),
    ]
    for tool_name, tool_slug in tools:
        tool_id = f"{base_uri}/Tool/{tool_slug}"
        agents.append({
            "@type": "Tool",
            "@id": tool_id,
            "creationInfo": "_:creationinfo",
            "name": tool_name,
        })
        created_using_ids.append(tool_id)

    creation_info = {
        "@type": "CreationInfo",
        "@id": "_:creationinfo",
        "specVersion": "3.0.1",
        "created": now,
        "createdBy": created_by_ids,
        "createdUsing": created_using_ids,
    }

    return creation_info, agents


def _make_license_elements(
    element_id: str, license_expr: str, rel_type: str,
    base_uri: str, counter: list[int],
) -> tuple[dict, dict]:
    """Create a LicenseExpression element and linking Relationship."""
    idx = counter[0]
    counter[0] += 1

    lic_id = f"{base_uri}/LicenseExpression/{idx}"
    rel_id = f"{base_uri}/LicenseRelationship/{idx}"

    return (
        {
            "@type": "simplelicensing_LicenseExpression",
            "@id": lic_id,
            "creationInfo": "_:creationinfo",
            "simplelicensing_licenseExpression": license_expr,
        },
        {
            "@type": "Relationship",
            "@id": rel_id,
            "creationInfo": "_:creationinfo",
            "from": element_id,
            "to": [lic_id],
            "relationshipType": rel_type,
        },
    )


def build_file_elements(
    files: list[dict], base_uri: str, lic_counter: list[int],
) -> tuple[list[dict], list[dict]]:
    """Build software_File + license Relationship elements.

    Every file from the filesystem walk becomes an element —
    complete inventory, not just files with findings.
    """
    file_elements = []
    lic_elements = []

    for idx, f in enumerate(files):
        file_id = f"{base_uri}/File/{idx}"
        sha = f.get("sha256", "")

        elem = {
            "@type": "software_File",
            "@id": file_id,
            "creationInfo": "_:creationinfo",
            "name": f["path"],
        }

        if sha:
            elem["verifiedUsing"] = [{"@type": "Hash", "algorithm": "sha256", "hashValue": sha}]

        if f.get("copyrights"):
            elem["software_copyrightText"] = "\n".join(f["copyrights"])

        if f.get("purpose") and f["purpose"] in VALID_PURPOSES:
            elem["software_primaryPurpose"] = f["purpose"]

        if f.get("mime_type"):
            elem["software_contentType"] = f["mime_type"]

        # Store the element ID back for relationship building
        f["_element_id"] = file_id

        file_elements.append(elem)

        # FOSSology-detected license → hasConcludedLicense
        for lic_str in f.get("licenses", []):
            if lic_str and lic_str not in ("NOASSERTION", "NONE"):
                lic_el, rel_el = _make_license_elements(
                    file_id, lic_str, "hasConcludedLicense", base_uri, lic_counter,
                )
                lic_elements.extend([lic_el, rel_el])

    return file_elements, lic_elements


def build_structural_relationships(
    files: list[dict], doc_id: str, root_pkg_id: str, base_uri: str,
) -> list[dict]:
    rels = []
    idx = 0

    rels.append({
        "@type": "Relationship",
        "@id": f"{base_uri}/Relationship/{idx}",
        "creationInfo": "_:creationinfo",
        "from": doc_id,
        "to": [root_pkg_id],
        "relationshipType": "describes",
    })
    idx += 1

    for f in files:
        fid = f.get("_element_id")
        if fid:
            rels.append({
                "@type": "Relationship",
                "@id": f"{base_uri}/Relationship/{idx}",
                "creationInfo": "_:creationinfo",
                "from": root_pkg_id,
                "to": [fid],
                "relationshipType": "contains",
            })
            idx += 1

    return rels


# ═════════════════════════════════════════════════════════════════════
# Phase 3: Validation
# ═════════════════════════════════════════════════════════════════════

def validate_element(element: dict, errors: list[str]) -> None:
    """Validate a single SPDX 3.0 element."""
    etype = element.get("@type", "?")

    if etype not in VALID_TYPES:
        errors.append(f"Unknown @type '{etype}' on {element.get('@id', '?')}")

    for field in REQUIRED_FIELDS.get(etype, []):
        if field not in element:
            errors.append(f"{etype} {element.get('@id', '?')}: missing '{field}'")

    if etype == "Relationship":
        rt = element.get("relationshipType", "")
        if rt not in VALID_RELATIONSHIP_TYPES:
            errors.append(f"Relationship {element.get('@id', '?')}: invalid type '{rt}'")
        if not isinstance(element.get("to"), list):
            errors.append(f"Relationship {element.get('@id', '?')}: 'to' must be a list")

    purpose = element.get("software_primaryPurpose")
    if purpose and purpose not in VALID_PURPOSES:
        errors.append(f"{etype} {element.get('@id', '?')}: invalid purpose '{purpose}'")

    for h in element.get("verifiedUsing", []):
        algo = h.get("algorithm", "")
        if algo and algo not in VALID_HASH_ALGORITHMS:
            errors.append(f"Hash: invalid algorithm '{algo}'")


# ═════════════════════════════════════════════════════════════════════
# Phase 4: Main Build Orchestrator
# ═════════════════════════════════════════════════════════════════════

def build(
    repo_root: str,
    report_dir: str | None,
    output_path: str,
    findings_override: dict | None = None,
    findings_file: str | None = None,
) -> None:

    repo_root = os.path.abspath(repo_root)
    doc_name = os.environ.get("GITHUB_REPOSITORY", os.path.basename(repo_root))

    print(f"\n{'='*60}")
    print(f"SPDX 3.0 Direct Builder")
    print(f"{'='*60}\n")

    print("[Phase 1] Collecting data...\n")

    if findings_override is not None:
        findings = findings_override
        print(f"  Using {len(findings)} file(s) from direct scanner input")
    elif findings_file:
        with open(findings_file, 'r', encoding='utf-8') as f:
            findings = json.load(f)
        print(f"  Loaded {len(findings)} file(s) from {findings_file}")
    else:
        findings = {}
        print("  No findings provided")

    files = []
    for path, data in findings.items():
        files.append({
            "path": path,
            "sha256": data.get("checksums", {}).get("sha256", ""),
            "licenses": data.get("licenses", []),
            "copyrights": data.get("copyrights", []),
            "mime_type": "",
            "purpose": "file",
        })

    files_with_cr = sum(1 for f in files if f.get("copyrights"))
    print(f"  Files from agent findings: {len(files)}")
    print(f"  Files with copyright data: {files_with_cr}")

    print(f"\n[Phase 2] Building SPDX 3.0 elements...\n")

    base_uri = generate_base_uri(doc_name)
    doc_id = f"{base_uri}/Document"
    lic_counter = [0]

    creation_info, agent_elements = build_creation_info(base_uri)
    print(f"  CreationInfo: {len(agent_elements)} agent/tool elements")

    file_elements, file_lic_elements = build_file_elements(files, base_uri, lic_counter)
    print(f"  Files: {len(file_elements)} elements, {len(file_lic_elements)} license elements")

    root_pkg_id = f"{base_uri}/Package/{re.sub(r'[^a-zA-Z0-9._-]', '-', doc_name)}"
    root_pkg = {
        "@type": "software_Package",
        "@id": root_pkg_id,
        "creationInfo": "_:creationinfo",
        "name": doc_name,
        "software_primaryPurpose": "application",
    }

    rel_elements = build_structural_relationships(files, doc_id, root_pkg_id, base_uri)
    print(f"  Relationships: {len(rel_elements)} elements")

    all_elements = (
        agent_elements + [root_pkg] + file_elements +
        rel_elements + file_lic_elements
    )
    all_element_ids = [e["@id"] for e in all_elements]

    profiles = ["core", "software"]
    if file_lic_elements:
        profiles.append("licensing")

    spdx_document = {
        "@type": "SpdxDocument",
        "@id": doc_id,
        "creationInfo": "_:creationinfo",
        "specVersion": "3.0.1",
        "name": doc_name,
        "dataLicense": "CC0-1.0",
        "profileConformance": profiles,
        "rootElement": [root_pkg_id],
        "element": all_element_ids,
    }

    graph = [creation_info, spdx_document] + all_elements

    print(f"\n[Phase 3] Validation...\n")

    all_errors = []
    for elem in graph:
        validate_element(elem, all_errors)
    if all_errors:
        print(f"  Validation: {len(all_errors)} issue(s):")
        for err in all_errors[:10]:
            print(f"    - {err}")
        if len(all_errors) > 10:
            print(f"    ... and {len(all_errors) - 10} more")
    else:
        print("  Validation passed: all elements conform to SPDX 3.0")

    print(f"\n[Phase 4] Serializing output...\n")

    spdx3_doc = {"@context": SPDX_CONTEXT, "@graph": graph}

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(spdx3_doc, f, indent=4, ensure_ascii=False)
    print(f"  SPDX 3.0 JSON-LD written to: {output_path}")

    print(f"\n{'='*60}")
    print(f"  Build Summary")
    print(f"{'='*60}")
    print(f"  Profiles:        {', '.join(profiles)}")
    print(f"  Total elements:  {len(all_element_ids)}")
    print(f"    Agents/Tools:  {len(agent_elements)}")
    print(f"    Packages:      1")
    print(f"    Files:         {len(file_elements)}")
    print(f"    Relationships: {len(rel_elements)}")
    print(f"    License Elems: {len(file_lic_elements)}")
    print(f"  Document URI:    {doc_id}")
    print()


# ═════════════════════════════════════════════════════════════════════
# CLI Entry Point
# ═════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="SPDX 3.0 Report Builder — generates SPDX 3.0 JSON-LD from raw data sources.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic: build from repo + FOSSology report
  python spdx3_builder.py --repo-root . --fossology-report results/ --output results/spdx3_report.jsonld

  # Without FOSSology (lock files + filesystem only)
  python spdx3_builder.py --repo-root . --output results/spdx3_report.jsonld
        """,
    )
    parser.add_argument("--repo-root", required=True, help="Path to repository root directory")
    parser.add_argument("--fossology-report", default=None, help="Path to directory containing FOSSology report files")
    parser.add_argument("--output", required=True, help="Output path for SPDX 3.0 JSON-LD file")

    args = parser.parse_args()

    if not os.path.isdir(args.repo_root):
        print(f"Error: repo-root '{args.repo_root}' is not a directory")
        sys.exit(1)

    build(
        repo_root=args.repo_root,
        report_dir=args.fossology_report,
        output_path=args.output,
    )


if __name__ == "__main__":
    main()
