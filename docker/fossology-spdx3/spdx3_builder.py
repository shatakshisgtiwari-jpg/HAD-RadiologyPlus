#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Contributors
# SPDX-License-Identifier: MIT

"""SPDX 3.0 Report Builder -- generates JSON-LD from FOSSology agent findings.

Uses the official spdx-tools Python library for model construction and
JSON-LD serialization instead of hardcoded context/constants.
"""

import argparse
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone

from semantic_version import Version

from spdx_tools.spdx3.model import (
    CreationInfo,
    Hash,
    HashAlgorithm,
    Organization,
    ProfileIdentifierType,
    Tool,
    Relationship,
    RelationshipType,
    SpdxDocument,
)
from spdx_tools.spdx3.model.software import (
    File as SpdxFile,
    Package,
    SoftwarePurpose,
)
from spdx_tools.spdx3.model.licensing import CustomLicense
from spdx_tools.spdx3.payload import Payload
from spdx_tools.spdx3.writer.json_ld.json_ld_writer import write_payload


HASH_ALGO_MAP = {
    "sha256": HashAlgorithm.SHA256,
    "sha1": HashAlgorithm.SHA1,
    "md5": HashAlgorithm.MD5,
    "sha384": HashAlgorithm.SHA384,
    "sha512": HashAlgorithm.SHA512,
}


SPDX3_JSON_SCHEMA_URL = "https://spdx.org/schema/3.0.1/spdx-json-schema.json"
SPDX3_SHACL_URL = "https://spdx.org/rdf/3.0.1/spdx-model.ttl"


def _validate_report(report_path: str) -> None:
    """Validate the generated SPDX 3.0 JSON-LD report.

    Runs two checks:
      1. JSON Schema (structural) — via check-jsonschema or jsonschema
      2. SHACL (semantic) — via pyshacl
    Failures are logged as warnings but do not block the pipeline.
    """
    passed = 0
    failed = 0

    # ── 1. JSON Schema validation ──
    try:
        import jsonschema
        import urllib.request

        print("  [Validation] Downloading SPDX 3.0 JSON Schema...")
        with urllib.request.urlopen(SPDX3_JSON_SCHEMA_URL) as resp:
            schema = json.loads(resp.read().decode('utf-8'))

        with open(report_path, 'r', encoding='utf-8') as f:
            doc = json.load(f)

        validator = jsonschema.Draft202012Validator(schema)
        errors = list(validator.iter_errors(doc))
        if errors:
            failed += 1
            print(f"  [Validation] JSON Schema: FAILED ({len(errors)} error(s))")
            for err in errors[:5]:
                print(f"    - {err.message[:200]}")
            if len(errors) > 5:
                print(f"    ... and {len(errors) - 5} more")
        else:
            passed += 1
            print("  [Validation] JSON Schema: PASSED")
    except ImportError:
        print("  [Validation] JSON Schema: SKIPPED (jsonschema not installed)")
    except Exception as e:
        print(f"  [Validation] JSON Schema: ERROR ({e})")

    # ── 2. SHACL validation (semantic) ──
    try:
        from pyshacl import validate as shacl_validate
        from rdflib import Graph

        print("  [Validation] Running SHACL validation against SPDX 3.0 model...")
        data_graph = Graph()
        data_graph.parse(report_path, format="json-ld")

        conforms, results_graph, results_text = shacl_validate(
            data_graph=data_graph,
            shacl_graph=SPDX3_SHACL_URL,
            ont_graph=SPDX3_SHACL_URL,
        )
        if conforms:
            passed += 1
            print("  [Validation] SHACL: PASSED")
        else:
            failed += 1
            # Show first few violations
            lines = results_text.strip().split('\n')
            print(f"  [Validation] SHACL: FAILED")
            for line in lines[:10]:
                print(f"    {line}")
            if len(lines) > 10:
                print(f"    ... and {len(lines) - 10} more lines")
    except ImportError:
        print("  [Validation] SHACL: SKIPPED (pyshacl not installed)")
    except Exception as e:
        print(f"  [Validation] SHACL: ERROR ({e})")

    print(f"\n  Validation summary: {passed} passed, {failed} failed")


def _base_uri(doc_name: str) -> str:
    unique = uuid.uuid4().hex[:12]
    safe = re.sub(r"[^a-zA-Z0-9._-]", "-", doc_name)
    return f"urn:spdx:{safe}/{unique}"


def _make_creation_info(base_uri: str, org_element_id: str, tool_ids: list[str]) -> CreationInfo:
    return CreationInfo(
        spec_version=Version("3.0.1"),
        created=datetime.now(timezone.utc),
        created_by=[org_element_id],
        created_using=tool_ids,
        profile=[ProfileIdentifierType.CORE, ProfileIdentifierType.SOFTWARE],
    )


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
    print(f"SPDX 3.0 Builder (spdx-tools)")
    print(f"{'='*60}\n")

    # ── Phase 1: Collect findings ────────────────────────────────
    print("[Phase 1] Collecting data...\n")

    if findings_override is not None:
        findings = findings_override
        print(f"  Using {len(findings)} file(s) from direct scanner input")
    elif findings_file:
        with open(findings_file, 'r', encoding='utf-8') as fh:
            findings = json.load(fh)
        print(f"  Loaded {len(findings)} file(s) from {findings_file}")
    else:
        findings = {}
        print("  No findings provided")

    print(f"  Files from agent findings: {len(findings)}")
    print(f"  Files with copyright data: {sum(1 for d in findings.values() if d.get('copyrights'))}")
    print(f"  Files with license data: {sum(1 for d in findings.values() if d.get('licenses'))}")

    # ── Phase 2: Build SPDX 3.0 model elements ──────────────────
    print(f"\n[Phase 2] Building SPDX 3.0 elements...\n")

    base = _base_uri(doc_name)
    payload = Payload()

    # -- Agents & Tools --
    org_name = os.environ.get("GITHUB_REPOSITORY_OWNER",
               os.environ.get("GITHUB_REPO_OWNER", "Unknown"))
    org_id = f"{base}/Agent/{re.sub(r'[^a-zA-Z0-9]', '', org_name)}"
    tool1_id = f"{base}/Tool/fossology-scanner"
    tool2_id = f"{base}/Tool/spdx3-builder"

    # CreationInfo needs the org/tool IDs; the objects themselves need CreationInfo.
    # spdx-tools allows passing spdx_id strings in created_by / created_using.
    cinfo = _make_creation_info(base, org_id, [tool1_id, tool2_id])

    org_elem = Organization(spdx_id=org_id, creation_info=cinfo, name=org_name)
    tool1 = Tool(spdx_id=tool1_id, creation_info=cinfo, name="FOSSology CI Scanner")
    tool2 = Tool(spdx_id=tool2_id, creation_info=cinfo, name="spdx3-builder")

    for elem in (org_elem, tool1, tool2):
        payload.add_element(elem)
    print(f"  Agents/Tools: 3 elements")

    # -- Root Package --
    safe_pkg = re.sub(r"[^a-zA-Z0-9._-]", "-", doc_name)
    root_pkg_id = f"{base}/Package/{safe_pkg}"
    root_pkg = Package(
        spdx_id=root_pkg_id,
        name=doc_name,
        creation_info=cinfo,
        primary_purpose=SoftwarePurpose.APPLICATION,
    )
    payload.add_element(root_pkg)

    # -- File elements + relationships --
    file_ids = []
    rel_idx = 0

    for fidx, (path, data) in enumerate(findings.items()):
        # Skip files with no findings — they add no value to the report
        if not data.get("copyrights") and not data.get("licenses"):
            continue

        file_id = f"{base}/File/{fidx}"

        hashes = []
        sha = data.get("checksums", {}).get("sha256", "")
        if sha:
            hashes.append(Hash(algorithm=HashAlgorithm.SHA256, hash_value=sha))

        copyright_text = None
        if data.get("copyrights"):
            copyright_text = "\n".join(data["copyrights"])

        # In SPDX 3.0, concluded_license is a property on File, not a relationship.
        # Build a LicenseField if license findings exist.
        concluded_license = None
        licenses = [l for l in data.get("licenses", []) if l and l not in ("NOASSERTION", "NONE")]
        if licenses:
            # Combine multiple licenses with AND (all detected in the file)
            lic_str = " AND ".join(sorted(set(licenses)))
            concluded_license = CustomLicense(
                license_id=lic_str,
                license_name=lic_str,
                license_text=lic_str,
            )

        f_elem = SpdxFile(
            spdx_id=file_id,
            name=path,
            creation_info=cinfo,
            copyright_text=copyright_text,
            verified_using=hashes if hashes else None,
            primary_purpose=SoftwarePurpose.FILE,
            concluded_license=concluded_license,
        )
        payload.add_element(f_elem)
        file_ids.append(file_id)

    print(f"  Files: {len(file_ids)} elements")

    # -- Structural relationships --
    struct_rels = 0

    # Package CONTAINS each File
    for fid in file_ids:
        contains_rel = Relationship(
            spdx_id=f"{base}/Relationship/{rel_idx}",
            from_element=root_pkg_id,
            relationship_type=RelationshipType.CONTAINS,
            to=[fid],
            creation_info=cinfo,
        )
        payload.add_element(contains_rel)
        rel_idx += 1
        struct_rels += 1

    print(f"  Relationships: {rel_idx} elements (structural: {struct_rels})")

    # -- SpdxDocument --
    doc_id = f"{base}/Document"
    all_ids = [e.spdx_id for e in payload.get_full_map().values()]

    # Document DESCRIBES the root package (added after doc creation)
    describes_rel_id = f"{base}/Relationship/{rel_idx}"
    all_ids.append(describes_rel_id)

    spdx_doc = SpdxDocument(
        spdx_id=doc_id,
        name=doc_name,
        element=all_ids,
        root_element=[root_pkg_id],
        creation_info=cinfo,
    )
    payload.add_element(spdx_doc)

    describes_rel = Relationship(
        spdx_id=describes_rel_id,
        from_element=doc_id,
        relationship_type=RelationshipType.DESCRIBES,
        to=[root_pkg_id],
        creation_info=cinfo,
    )
    payload.add_element(describes_rel)
    rel_idx += 1

    # ── Phase 3: Serialize to JSON-LD ────────────────────────────
    print(f"\n[Phase 3] Serializing output...\n")

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    # write_payload appends .jsonld, so strip it if present
    out_base = output_path
    if out_base.endswith(".jsonld"):
        out_base = out_base[:-7]

    write_payload(payload, out_base)
    actual_path = out_base + ".jsonld"

    size = os.path.getsize(actual_path)
    print(f"  SPDX 3.0 JSON-LD written to: {actual_path}")

    # ── Phase 4: Validate the report ─────────────────────────────
    print(f"\n[Phase 4] Validating SPDX 3.0 report...\n")
    _validate_report(actual_path)

    total = len(payload.get_full_map())
    print(f"\n{'='*60}")
    print(f"  Build Summary")
    print(f"{'='*60}")
    print(f"  Total elements:  {total}")
    print(f"    Agents/Tools:  3")
    print(f"    Packages:      1")
    print(f"    Files:         {len(file_ids)}")
    print(f"    Relationships: {rel_idx}")
    print(f"  Document URI:    {doc_id}")
    print(f"  Output size:     {size} bytes")
    print()


# ═════════════════════════════════════════════════════════════════════
# CLI Entry Point
# ═════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="SPDX 3.0 Report Builder — generates SPDX 3.0 JSON-LD from raw data sources.",
    )
    parser.add_argument("--repo-root", required=True, help="Path to repository root directory")
    parser.add_argument("--fossology-report", default=None, help="Path to FOSSology report directory")
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
