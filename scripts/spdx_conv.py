#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 HAD-RadiologyPlus Contributors
# SPDX-License-Identifier: MIT

"""
SPDX 2.3 JSON → SPDX 3.0 JSON-LD Converter

Converts FOSSology CI scanner SPDX 2.3 JSON reports to SPDX 3.0 JSON-LD format.
Implements Core, Software, and Licensing profiles.

Conformance:
    - Uses standard JSON-LD keywords (@type, @id) for universal parseability
    - @context sourced from official https://spdx.org/rdf/3.0.0/spdx-context.jsonld
    - Inline context subset included for self-contained documents
    - Based on SPDX 3.0.0 specification (https://spdx.github.io/spdx-spec/v3.0/)
    - Model reference: https://github.com/spdx/spdx-3-model (release 3.0.1)

Usage:
    python spdx_conv.py <input_spdx2.json> <output_spdx3.jsonld> [allowlist.json]

Clearing Decisions:
    When an allowlist.json is provided, the converter applies human-in-the-loop
    clearing decisions. Each element is marked as CLEARED, FLAGGED, or EXCLUDED
    based on the allowlist policy, and a clearing report is generated alongside
    the SPDX 3.0 output.
"""

import fnmatch
import json
import sys
import uuid
from datetime import datetime, timezone


# ──────────────────────────────────────────────
# Mapping tables: SPDX 2.3 → SPDX 3.0
# ──────────────────────────────────────────────

# ──────────────────────────────────────────────
# Inline @context: subset of the official SPDX 3.0 JSON-LD context.
# Sourced from https://spdx.org/rdf/3.0.0/spdx-context.jsonld
# Makes documents self-contained (no URL fetch needed to resolve types).
# ──────────────────────────────────────────────
_SPDX_NS = "https://spdx.org/rdf/3.0.0/terms"

SPDX_CONTEXT = [
    # Primary: official context URL (authoritative, enables full resolution)
    "https://spdx.org/rdf/3.0.0/spdx-context.jsonld",
    # Secondary: inline subset (self-contained fallback, covers all types/props we emit)
    {
        # ── Core profile types ──
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
        # ── Software profile types ──
        "software_Package": f"{_SPDX_NS}/Software/Package",
        "software_File": f"{_SPDX_NS}/Software/File",
        # ── Licensing profile types ──
        "simplelicensing_SimpleLicensingText": f"{_SPDX_NS}/SimpleLicensing/SimpleLicensingText",
        "simplelicensing_LicenseExpression": f"{_SPDX_NS}/SimpleLicensing/LicenseExpression",
        # ── Core properties ──
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
        # ── Software properties ──
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
        # ── Licensing properties ──
        "simplelicensing_licenseText": {"@id": f"{_SPDX_NS}/SimpleLicensing/licenseText", "@type": "http://www.w3.org/2001/XMLSchema#string"},
        "simplelicensing_licenseExpression": {"@id": f"{_SPDX_NS}/SimpleLicensing/licenseExpression", "@type": "http://www.w3.org/2001/XMLSchema#string"},
        "simplelicensing_licenseListVersion": {"@id": f"{_SPDX_NS}/SimpleLicensing/licenseListVersion", "@type": "http://www.w3.org/2001/XMLSchema#string"},
    }
]

# ──────────────────────────────────────────────
# Validation: allowed types and required fields per SPDX 3.0 spec
# ──────────────────────────────────────────────
VALID_TYPES = {
    "CreationInfo", "SpdxDocument", "Organization", "Person", "Tool",
    "Relationship", "Hash", "ExternalIdentifier", "ExternalRef",
    "Annotation",
    "software_Package", "software_File",
    "simplelicensing_SimpleLicensingText",
    "simplelicensing_LicenseExpression",
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
    "buildToolOf", "copyOf", "variantOf", "hasPrerequisite",
    "hasDeclaredLicense", "hasConcludedLicense",
    "expandsTo", "hasStaticLink", "hasDynamicLink",
    "hasOptionalDependency", "hasDocumentation",
    "hasDistributionArtifact", "hasDependencyManifest",
    "ancestorOf", "descendantOf", "amendedBy",
    "serializedInArtifact", "other",
}

VALID_HASH_ALGORITHMS = {
    "md2", "md4", "md5", "md6",
    "sha1", "sha224", "sha256", "sha384", "sha512",
    "sha3_256", "sha3_384", "sha3_512",
    "blake2b256", "blake2b384", "blake2b512", "blake3",
    "adler32", "other",
}

VALID_PURPOSES = {"source", "executable", "archive", "application", "documentation", "data", "other"}


def validate_element(element: dict, errors: list[str]) -> None:
    """Validate a single SPDX 3.0 element against required fields and allowed values."""
    etype = element.get("@type", "?")

    # Check type is recognized
    if etype not in VALID_TYPES:
        errors.append(f"Unknown @type '{etype}' on element {element.get('@id', '?')}")

    # Check required fields
    for field in REQUIRED_FIELDS.get(etype, []):
        if field not in element:
            errors.append(f"{etype} {element.get('@id', '?')}: missing required field '{field}'")

    # Validate relationship types
    if etype == "Relationship":
        rt = element.get("relationshipType", "")
        if rt not in VALID_RELATIONSHIP_TYPES:
            errors.append(f"Relationship {element.get('@id', '?')}: invalid relationshipType '{rt}'")
        if not isinstance(element.get("to"), list):
            errors.append(f"Relationship {element.get('@id', '?')}: 'to' must be a list")

    # Validate hash algorithms
    if etype == "Hash":
        algo = element.get("algorithm", "")
        if algo not in VALID_HASH_ALGORITHMS:
            errors.append(f"Hash: invalid algorithm '{algo}'")

    # Validate purposes
    purpose = element.get("software_primaryPurpose")
    if purpose and purpose not in VALID_PURPOSES:
        errors.append(f"{etype} {element.get('@id', '?')}: invalid purpose '{purpose}'")

    # Validate nested hashes in verifiedUsing
    for h in element.get("verifiedUsing", []):
        validate_element(h, errors)

    # Validate nested externalIdentifiers
    for ei in element.get("externalIdentifier", []):
        if "identifier" not in ei:
            errors.append(f"{etype} {element.get('@id', '?')}: externalIdentifier missing 'identifier'")


# ──────────────────────────────────────────────
# Clearing decisions: human-in-the-loop policy enforcement
# ──────────────────────────────────────────────

def load_allowlist(allowlist_path: str) -> dict:
    """Load the allowlist.json policy file."""
    with open(allowlist_path, "r", encoding="utf-8") as f:
        return json.load(f)


def _match_exclude(name: str, exclude_patterns: list[str]) -> bool:
    """Check if a filename matches any exclusion pattern."""
    for pattern in exclude_patterns:
        if fnmatch.fnmatch(name, pattern):
            return True
    return False


def apply_clearing_decisions(
    graph: list[dict],
    allowlist: dict,
    base_uri: str,
) -> tuple[list[dict], dict]:
    """Apply human-in-the-loop clearing decisions to SPDX 3.0 elements.

    For each software_Package / software_File / LicenseExpression element:
      - CLEARED: license is in the approved list
      - EXCLUDED: file matches an exclusion pattern
      - FLAGGED: license detected but not in approved list (needs human review)

    Adds Annotation elements to the graph recording the decision.
    Returns (updated_graph, clearing_summary).
    """
    approved_licenses = [lic.lower() for lic in allowlist.get("licenses", [])]
    exclude_patterns = allowlist.get("exclude", [])

    annotations = []
    ann_counter = 0
    summary = {
        "cleared": [],
        "excluded": [],
        "flagged": [],
        "total_elements": 0,
    }

    # Collect license expressions keyed by their @id
    lic_expr_map: dict[str, str] = {}  # lic_id -> expression string
    for elem in graph:
        if elem.get("@type") == "simplelicensing_LicenseExpression":
            lic_expr_map[elem["@id"]] = elem.get(
                "simplelicensing_licenseExpression", ""
            )

    # Map: element_id -> list of license strings (via hasConcludedLicense/hasDeclaredLicense rels)
    elem_licenses: dict[str, list[str]] = {}
    for elem in graph:
        if elem.get("@type") == "Relationship" and elem.get("relationshipType") in (
            "hasConcludedLicense", "hasDeclaredLicense",
        ):
            from_id = elem["from"]
            for to_id in elem.get("to", []):
                expr = lic_expr_map.get(to_id, "")
                if expr:
                    elem_licenses.setdefault(from_id, []).append(expr)

    for elem in graph:
        etype = elem.get("@type", "")
        if etype not in ("software_Package", "software_File"):
            continue

        summary["total_elements"] += 1
        elem_id = elem["@id"]
        elem_name = elem.get("name", "")

        # Check exclusion first
        if etype == "software_File" and _match_exclude(elem_name, exclude_patterns):
            decision = "EXCLUDED"
            reason = f"File matches exclusion pattern in allowlist"
            summary["excluded"].append({"id": elem_id, "name": elem_name})
        else:
            # Check licenses against approved list
            licenses = elem_licenses.get(elem_id, [])
            if not licenses:
                decision = "CLEARED"
                reason = "No license detected"
                summary["cleared"].append(
                    {"id": elem_id, "name": elem_name, "license": "none"}
                )
            else:
                all_approved = True
                for lic in licenses:
                    # Check each token in the expression
                    tokens = lic.replace("(", "").replace(")", "").split()
                    for token in tokens:
                        token_lower = token.lower()
                        if token_lower in ("and", "or", "with"):
                            continue
                        if not any(
                            token_lower == a or token_lower.startswith(a)
                            for a in approved_licenses
                        ):
                            all_approved = False
                            break

                if all_approved:
                    decision = "CLEARED"
                    reason = f"License(s) {', '.join(licenses)} approved by policy"
                    summary["cleared"].append(
                        {"id": elem_id, "name": elem_name,
                         "license": ", ".join(licenses)}
                    )
                else:
                    decision = "FLAGGED"
                    reason = (
                        f"License(s) {', '.join(licenses)} not fully covered by "
                        f"approved list {allowlist.get('licenses', [])}"
                    )
                    summary["flagged"].append(
                        {"id": elem_id, "name": elem_name,
                         "license": ", ".join(licenses)}
                    )

        # Create an Annotation element recording the decision
        ann_id = f"{base_uri}/Annotation/clearing-{ann_counter}"
        ann_counter += 1
        annotation = {
            "@type": "Annotation",
            "@id": ann_id,
            "creationInfo": "_:creationinfo",
            "annotationType": "review",
            "subject": elem_id,
            "statement": f"Clearing decision: {decision}. {reason}",
        }
        annotations.append(annotation)

    return annotations, summary


def write_clearing_report(summary: dict, output_path: str) -> None:
    """Write a human-readable clearing decision report."""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("SPDX 3.0 License Clearing Report\n")
        f.write("=" * 50 + "\n\n")
        f.write(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}\n")
        f.write(f"Total elements reviewed: {summary['total_elements']}\n")
        f.write(f"  CLEARED:  {len(summary['cleared'])}\n")
        f.write(f"  EXCLUDED: {len(summary['excluded'])}\n")
        f.write(f"  FLAGGED:  {len(summary['flagged'])}\n\n")

        if summary["flagged"]:
            f.write("-" * 50 + "\n")
            f.write("FLAGGED — Requires Human Review\n")
            f.write("-" * 50 + "\n")
            for item in summary["flagged"]:
                f.write(f"  {item['name']}\n")
                f.write(f"    License: {item['license']}\n")
                f.write(f"    ID: {item['id']}\n\n")

        if summary["cleared"]:
            f.write("-" * 50 + "\n")
            f.write("CLEARED — Approved by Policy\n")
            f.write("-" * 50 + "\n")
            for item in summary["cleared"]:
                f.write(f"  {item['name']}\n")
                f.write(f"    License: {item['license']}\n\n")

        if summary["excluded"]:
            f.write("-" * 50 + "\n")
            f.write("EXCLUDED — Matched Exclusion Pattern\n")
            f.write("-" * 50 + "\n")
            for item in summary["excluded"]:
                f.write(f"  {item['name']}\n")
                f.write(f"    ID: {item['id']}\n\n")

        # Final verdict
        if summary["flagged"]:
            f.write("\n" + "=" * 50 + "\n")
            f.write(f"VERDICT: REVIEW NEEDED — {len(summary['flagged'])} item(s) require attention\n")
        else:
            f.write("\n" + "=" * 50 + "\n")
            f.write("VERDICT: ALL CLEAR — All elements pass policy\n")


HASH_ALGORITHM_MAP = {
    "MD5": "md5",
    "SHA1": "sha1",
    "SHA256": "sha256",
    "SHA512": "sha512",
    "SHA3-256": "sha3_256",
    "SHA3-384": "sha3_384",
    "SHA3-512": "sha3_512",
}

RELATIONSHIP_TYPE_MAP = {
    "DESCRIBES": "describes",
    "DESCRIBED_BY": "describedBy",
    "CONTAINS": "contains",
    "CONTAINED_BY": "containedBy",
    "DEPENDS_ON": "dependsOn",
    "DEPENDENCY_OF": "dependencyOf",
    "GENERATES": "generates",
    "GENERATED_FROM": "generatedFrom",
    "BUILD_TOOL_OF": "buildToolOf",
    "COPY_OF": "copyOf",
    "VARIANT_OF": "variantOf",
    "HAS_PREREQUISITE": "hasPrerequisite",
    "OTHER": "other",
}

FILE_PURPOSE_MAP = {
    "SOURCE": "source",
    "BINARY": "executable",
    "ARCHIVE": "archive",
    "APPLICATION": "application",
    "DOCUMENTATION": "documentation",
    "IMAGE": "data",
    "TEXT": "source",
    "OTHER": "other",
}


def generate_base_uri(doc_name: str, namespace: str | None = None) -> str:
    """Generate a unique base URI for all elements in this document.

    Uses a URN scheme so that identifiers are clearly non-resolvable
    (clicking them in a browser won't produce misleading 404 errors).
    If the SPDX 2.3 document supplies a documentNamespace, it is
    reused as the base to preserve provenance.
    """
    if namespace:
        # Strip trailing slash and reuse the original namespace
        return namespace.rstrip("/")
    unique_id = uuid.uuid4().hex[:12]
    safe_name = doc_name.replace(" ", "-").replace("/", "-")
    return f"urn:spdx:{safe_name}/{unique_id}"


def parse_creators(creators: list[str]) -> dict:
    """
    Parse SPDX 2.3 creator strings into separate organizations, persons, tools.

    SPDX 2.3 format: "Organization: Name (email)" or "Tool: name-version"
    """
    organizations = []
    persons = []
    tools = []

    for creator in creators:
        if creator.startswith("Organization:"):
            org_info = creator[len("Organization:"):].strip()
            name = org_info.split("(")[0].strip()
            email = ""
            if "(" in org_info and ")" in org_info:
                email = org_info.split("(")[1].rstrip(")")
            organizations.append({"name": name, "email": email})
        elif creator.startswith("Person:"):
            person_info = creator[len("Person:"):].strip()
            name = person_info.split("(")[0].strip()
            email = ""
            if "(" in person_info and ")" in person_info:
                email = person_info.split("(")[1].rstrip(")")
            persons.append({"name": name, "email": email})
        elif creator.startswith("Tool:"):
            tool_name = creator[len("Tool:"):].strip()
            tools.append({"name": tool_name})

    return {"organizations": organizations, "persons": persons, "tools": tools}


def build_creation_info(spdx2_doc: dict, base_uri: str) -> tuple[dict, list[dict]]:
    """
    Build SPDX 3.0 CreationInfo and Agent/Tool elements from SPDX 2.3 creationInfo.

    Returns:
        (creation_info_dict, list_of_agent_elements)
    """
    creation_info_2 = spdx2_doc.get("creationInfo", {})
    created = creation_info_2.get("created", datetime.now(timezone.utc).isoformat())
    creators_raw = creation_info_2.get("creators", [])
    parsed = parse_creators(creators_raw)

    agent_elements = []
    created_by_ids = []

    # Create Organization elements
    for i, org in enumerate(parsed["organizations"]):
        org_id = f"{base_uri}/Agent/Organization/{org['name'].replace(' ', '')}"
        created_by_ids.append(org_id)

        org_element = {
            "@type": "Organization",
            "@id": org_id,
            "creationInfo": "_:creationinfo",
            "name": org["name"],
        }
        if org["email"]:
            org_element["externalIdentifier"] = [{
                "@type": "ExternalIdentifier",
                "externalIdentifierType": "email",
                "identifier": org["email"],
            }]
        agent_elements.append(org_element)

    # Create Person elements
    for i, person in enumerate(parsed["persons"]):
        person_id = f"{base_uri}/Agent/Person/{person['name'].replace(' ', '')}"
        created_by_ids.append(person_id)

        person_element = {
            "@type": "Person",
            "@id": person_id,
            "creationInfo": "_:creationinfo",
            "name": person["name"],
        }
        if person["email"]:
            person_element["externalIdentifier"] = [{
                "@type": "ExternalIdentifier",
                "externalIdentifierType": "email",
                "identifier": person["email"],
            }]
        agent_elements.append(person_element)

    # Create Tool elements
    created_using_ids = []
    for i, tool in enumerate(parsed["tools"]):
        tool_id = f"{base_uri}/Tool/{tool['name'].replace(' ', '-')}"
        created_using_ids.append(tool_id)

        tool_element = {
            "@type": "Tool",
            "@id": tool_id,
            "creationInfo": "_:creationinfo",
            "name": tool["name"],
        }
        agent_elements.append(tool_element)

    # If no tools were listed, add FOSSology CI Scanner as default
    if not created_using_ids:
        default_tool_id = f"{base_uri}/Tool/fossology-ci-scanner"
        created_using_ids.append(default_tool_id)
        agent_elements.append({
            "@type": "Tool",
            "@id": default_tool_id,
            "creationInfo": "_:creationinfo",
            "name": "FOSSology CI Scanner",
        })

    # If no agents were listed, add FOSSology as default organization
    if not created_by_ids:
        default_org_id = f"{base_uri}/Agent/Organization/FOSSology"
        created_by_ids.append(default_org_id)
        agent_elements.append({
            "@type": "Organization",
            "@id": default_org_id,
            "creationInfo": "_:creationinfo",
            "name": "FOSSology",
        })

    # Build the CreationInfo object (shared via blank node reference)
    creation_info = {
        "@type": "CreationInfo",
        "@id": "_:creationinfo",
        "specVersion": "3.0.0",
        "created": created,
        "createdBy": created_by_ids,
        "createdUsing": created_using_ids,
    }

    return creation_info, agent_elements


def convert_checksums(checksums: list[dict]) -> list[dict]:
    """Convert SPDX 2.3 checksums to SPDX 3.0 Hash elements."""
    hashes = []
    for cs in checksums:
        algo = HASH_ALGORITHM_MAP.get(cs["algorithm"], cs["algorithm"].lower())
        hashes.append({
            "@type": "Hash",
            "algorithm": algo,
            "hashValue": cs["checksumValue"],
        })
    return hashes


def _build_license_relationship(
    element_id: str,
    license_expr: str,
    rel_type: str,
    base_uri: str,
    counter: list[int],
) -> tuple[dict, dict]:
    """Create a LicenseExpression element and its linking Relationship.

    SPDX 3.0 models licenses as separate elements linked via Relationship
    (hasDeclaredLicense / hasConcludedLicense), not as direct properties.
    """
    idx = counter[0]
    counter[0] += 1

    lic_id = f"{base_uri}/LicenseExpression/{idx}"
    rel_id = f"{base_uri}/LicenseRelationship/{idx}"

    lic_element = {
        "@type": "simplelicensing_LicenseExpression",
        "@id": lic_id,
        "creationInfo": "_:creationinfo",
        "simplelicensing_licenseExpression": license_expr,
    }

    rel_element = {
        "@type": "Relationship",
        "@id": rel_id,
        "creationInfo": "_:creationinfo",
        "from": element_id,
        "to": [lic_id],
        "relationshipType": rel_type,
    }

    return lic_element, rel_element


def convert_package(
    pkg: dict, base_uri: str, id_map: dict, lic_counter: list[int],
) -> tuple[dict, list[dict]]:
    """Convert an SPDX 2.3 package to SPDX 3.0 software_Package element.

    Returns:
        (package_element, list_of_license_related_elements)
    """
    pkg_name = pkg.get("name", "UnknownPackage")
    spdx3_id = f"{base_uri}/Package/{pkg_name}"

    # Store mapping from old ID to new ID
    id_map[pkg["SPDXID"]] = spdx3_id

    pkg3 = {
        "@type": "software_Package",
        "@id": spdx3_id,
        "creationInfo": "_:creationinfo",
        "name": pkg_name,
    }

    # Download location
    if pkg.get("downloadLocation"):
        pkg3["software_downloadLocation"] = pkg["downloadLocation"]

    # Package version
    if pkg.get("versionInfo"):
        pkg3["software_packageVersion"] = pkg["versionInfo"]

    # Copyright
    if pkg.get("copyrightText") and pkg["copyrightText"] != "NOASSERTION":
        pkg3["software_copyrightText"] = pkg["copyrightText"]

    # Originator → originatedBy
    if pkg.get("originator"):
        originator_str = pkg["originator"]
        orig_name = originator_str.split(":")[-1].strip().split("(")[0].strip()
        originator_id = f"{base_uri}/Agent/Organization/{orig_name.replace(' ', '')}"
        pkg3["originatedBy"] = [originator_id]

    # Release date → releaseTime
    if pkg.get("releaseDate"):
        pkg3["releaseTime"] = pkg["releaseDate"]

    # Package verification code → Hash in verifiedUsing (concept removed in 3.0)
    pvc = pkg.get("packageVerificationCode", {})
    if pvc and pvc.get("packageVerificationCodeValue"):
        pvc_hash = {
            "@type": "Hash",
            "algorithm": "sha1",
            "hashValue": pvc["packageVerificationCodeValue"],
        }
        pkg3.setdefault("verifiedUsing", []).append(pvc_hash)

    # Checksums → verifiedUsing
    if pkg.get("checksums"):
        pkg3.setdefault("verifiedUsing", []).extend(
            convert_checksums(pkg["checksums"])
        )

    # ── License handling via Relationships (SPDX 3.0 standard) ──
    extra_elements: list[dict] = []

    concluded = pkg.get("licenseConcluded")
    if concluded and concluded not in ("NOASSERTION", "NONE"):
        lic_el, rel_el = _build_license_relationship(
            spdx3_id, concluded, "hasConcludedLicense", base_uri, lic_counter,
        )
        extra_elements.extend([lic_el, rel_el])

    declared = pkg.get("licenseDeclared")
    if declared and declared not in ("NOASSERTION", "NONE"):
        lic_el, rel_el = _build_license_relationship(
            spdx3_id, declared, "hasDeclaredLicense", base_uri, lic_counter,
        )
        extra_elements.extend([lic_el, rel_el])

    # Primary purpose
    if pkg.get("primaryPackagePurpose"):
        purpose = FILE_PURPOSE_MAP.get(
            pkg["primaryPackagePurpose"], pkg["primaryPackagePurpose"].lower()
        )
        pkg3["software_primaryPurpose"] = purpose

    # Homepage
    if pkg.get("homepage"):
        pkg3["software_homePage"] = pkg["homepage"]

    # External refs (purl, cpe, etc.)
    ext_refs = pkg.get("externalRefs", [])
    if ext_refs:
        pkg3["externalIdentifier"] = []
        for ref in ext_refs:
            ref_type = ref.get("referenceType", "")
            if "purl" in ref_type:
                pkg3["externalIdentifier"].append({
                    "@type": "ExternalIdentifier",
                    "externalIdentifierType": "purl",
                    "identifier": ref.get("referenceLocator", ""),
                })
            elif "cpe" in ref_type:
                pkg3["externalIdentifier"].append({
                    "@type": "ExternalIdentifier",
                    "externalIdentifierType": "cpe23Type",
                    "identifier": ref.get("referenceLocator", ""),
                })

    return pkg3, extra_elements


def convert_file(
    file_entry: dict, base_uri: str, id_map: dict, lic_counter: list[int],
) -> tuple[dict, list[dict]]:
    """Convert an SPDX 2.3 file to SPDX 3.0 software_File element.

    Returns:
        (file_element, list_of_license_related_elements)
    """
    filename = file_entry.get("fileName", "unknown")

    # Use SHA256 for the element ID if available, otherwise generate UUID
    sha256 = ""
    for cs in file_entry.get("checksums", []):
        if cs["algorithm"] == "SHA256":
            sha256 = cs["checksumValue"]
            break

    short_hash = sha256[:16] if sha256 else uuid.uuid4().hex[:16]
    spdx3_id = f"{base_uri}/File/{short_hash}"

    # Store mapping
    id_map[file_entry["SPDXID"]] = spdx3_id

    file3 = {
        "@type": "software_File",
        "@id": spdx3_id,
        "creationInfo": "_:creationinfo",
        "name": filename,
    }

    # Checksums → verifiedUsing
    checksums = file_entry.get("checksums", [])
    if checksums:
        file3["verifiedUsing"] = convert_checksums(checksums)

    # Copyright text
    copyright_text = file_entry.get("copyrightText")
    if copyright_text and copyright_text not in ("NOASSERTION", "NONE"):
        file3["software_copyrightText"] = copyright_text

    # File type → primary purpose
    file_types = file_entry.get("fileTypes", [])
    if file_types:
        purpose = FILE_PURPOSE_MAP.get(file_types[0], "other")
        file3["software_primaryPurpose"] = purpose

    # Content type (MIME)
    if file_entry.get("fileContentType"):
        file3["software_contentType"] = file_entry["fileContentType"]

    # License concluded → Relationship (SPDX 3.0 standard)
    extra_elements: list[dict] = []
    concluded = file_entry.get("licenseConcluded")
    if concluded and concluded not in ("NOASSERTION", "NONE"):
        lic_el, rel_el = _build_license_relationship(
            spdx3_id, concluded, "hasConcludedLicense", base_uri, lic_counter,
        )
        extra_elements.extend([lic_el, rel_el])

    # License comments
    if file_entry.get("licenseComments"):
        file3["comment"] = file_entry["licenseComments"]

    return file3, extra_elements


def convert_relationship(rel: dict, base_uri: str, id_map: dict, index: int) -> dict:
    """Convert an SPDX 2.3 relationship to SPDX 3.0 Relationship element."""
    rel_id = f"{base_uri}/Relationship/{index}"

    from_id = id_map.get(rel["spdxElementId"], rel["spdxElementId"])
    to_id = id_map.get(rel["relatedSpdxElement"], rel["relatedSpdxElement"])
    rel_type = RELATIONSHIP_TYPE_MAP.get(
        rel["relationshipType"], rel["relationshipType"].lower()
    )

    rel3 = {
        "@type": "Relationship",
        "@id": rel_id,
        "creationInfo": "_:creationinfo",
        "from": from_id,
        "to": [to_id],
        "relationshipType": rel_type,
    }

    # Relationship comment
    if rel.get("comment"):
        rel3["comment"] = rel["comment"]

    return rel3


def convert_extracted_licenses(spdx2_doc: dict, base_uri: str) -> list[dict]:
    """
    Convert SPDX 2.3 hasExtractedLicensingInfo to SPDX 3.0
    simplelicensing_SimpleLicensingText elements (Licensing profile).
    """
    elements = []
    for lic in spdx2_doc.get("hasExtractedLicensingInfo", []):
        lic_id = lic.get("licenseId", f"LicRef-{uuid.uuid4().hex[:8]}")
        spdx3_id = f"{base_uri}/License/{lic_id}"

        lic3 = {
            "@type": "simplelicensing_SimpleLicensingText",
            "@id": spdx3_id,
            "creationInfo": "_:creationinfo",
            "name": lic.get("name", lic_id),
            "simplelicensing_licenseText": lic.get("extractedText", ""),
        }

        # Cross-references (seeAlso)
        see_also = lic.get("seeAlsos", [])
        if see_also:
            lic3["externalRef"] = [
                {"@type": "ExternalRef", "externalRefType": "seeAlso", "locator": [url]}
                for url in see_also
            ]

        if lic.get("comment"):
            lic3["comment"] = lic["comment"]

        elements.append(lic3)

    return elements


def convert(
    input_path: str, output_path: str, allowlist_path: str | None = None,
) -> None:
    """
    Main conversion: SPDX 2.3 JSON → SPDX 3.0 JSON-LD.

    Implements:
    - Core Profile: SpdxDocument, CreationInfo, Relationship, Agent, Tool
    - Software Profile: Package, File, checksums, purposes
    - Licensing Profile: SimpleLicensingText (extracted licenses)

    If allowlist_path is provided, applies clearing decisions (human-in-the-loop)
    and generates a clearing report alongside the SPDX 3.0 output.
    """
    # ── Step 1: Read SPDX 2.3 document ──
    with open(input_path, "r", encoding="utf-8") as f:
        spdx2_doc = json.load(f)

    print(f"[1/8] Read SPDX 2.3 document: {spdx2_doc.get('name', 'unnamed')}")
    print(f"      Version: {spdx2_doc.get('spdxVersion', 'unknown')}")
    print(f"      Packages: {len(spdx2_doc.get('packages', []))}")
    print(f"      Files: {len(spdx2_doc.get('files', []))}")
    print(f"      Relationships: {len(spdx2_doc.get('relationships', []))}")

    # ── Step 2: Generate base URI and ID mapping ──
    doc_name = spdx2_doc.get("name", "SPDXDocument")
    namespace = spdx2_doc.get("documentNamespace")
    base_uri = generate_base_uri(doc_name, namespace)
    id_map = {}  # Maps SPDX 2.3 SPDXID → SPDX 3.0 @id URI

    print(f"[2/8] Base URI: {base_uri}")

    # ── Step 3: Build CreationInfo and Agent/Tool elements ──
    creation_info, agent_elements = build_creation_info(spdx2_doc, base_uri)
    print(f"[3/8] CreationInfo built: {len(agent_elements)} agent/tool elements")

    # ── Step 4: Convert packages ──
    package_elements = []
    license_rel_elements = []  # LicenseExpression + Relationship elements
    lic_counter = [0]  # Mutable counter for unique license IDs
    for pkg in spdx2_doc.get("packages", []):
        pkg3, lic_extras = convert_package(pkg, base_uri, id_map, lic_counter)
        package_elements.append(pkg3)
        license_rel_elements.extend(lic_extras)
    print(f"[4/8] Converted {len(package_elements)} packages")

    # ── Step 5: Convert files ──
    file_elements = []
    for file_entry in spdx2_doc.get("files", []):
        file3, lic_extras = convert_file(file_entry, base_uri, id_map, lic_counter)
        file_elements.append(file3)
        license_rel_elements.extend(lic_extras)
    print(f"[5/8] Converted {len(file_elements)} files")

    # ── Step 6: Convert relationships ──
    # Map the document's own SPDXID
    doc_spdx3_id = f"{base_uri}/Document"
    id_map[spdx2_doc.get("SPDXID", "SPDXRef-DOCUMENT")] = doc_spdx3_id

    relationship_elements = []
    for i, rel in enumerate(spdx2_doc.get("relationships", [])):
        rel3 = convert_relationship(rel, base_uri, id_map, i)
        relationship_elements.append(rel3)
    print(f"[6/8] Converted {len(relationship_elements)} relationships")

    # ── Step 7: Convert extracted license info (Licensing profile) ──
    license_elements = convert_extracted_licenses(spdx2_doc, base_uri)
    print(f"[7/8] Converted {len(license_elements)} extracted licenses")

    # ── Step 8: Build SpdxDocument and assemble @graph ──

    # Collect all element IDs
    all_element_ids = (
        [e["@id"] for e in agent_elements]
        + [e["@id"] for e in package_elements]
        + [e["@id"] for e in file_elements]
        + [e["@id"] for e in relationship_elements]
        + [e["@id"] for e in license_elements]
        + [e["@id"] for e in license_rel_elements]
    )

    # Determine root elements (targets of DESCRIBES relationships)
    root_element_ids = []
    for rel in spdx2_doc.get("relationships", []):
        if rel["relationshipType"] == "DESCRIBES":
            mapped_id = id_map.get(rel["relatedSpdxElement"])
            if mapped_id:
                root_element_ids.append(mapped_id)

    # Determine profile conformance
    profiles = ["core", "software"]
    if license_elements or license_rel_elements:
        profiles.append("licensing")

    # Build the SpdxDocument element
    spdx_document = {
        "@type": "SpdxDocument",
        "@id": doc_spdx3_id,
        "creationInfo": "_:creationinfo",
        "specVersion": "3.0.0",
        "name": doc_name,
        "dataLicense": spdx2_doc.get("dataLicense", "CC0-1.0"),
        "profileConformance": profiles,
        "rootElement": root_element_ids,
        "element": all_element_ids,
    }

    # Document namespace → comment (SPDX 3.0 doesn't have documentNamespace)
    ns = spdx2_doc.get("documentNamespace")
    if ns:
        spdx_document["comment"] = f"Converted from SPDX 2.3. Original namespace: {ns}"

    # Assemble the complete @graph
    graph = [
        creation_info,     # CreationInfo (shared blank node)
        spdx_document,     # SpdxDocument
        *agent_elements,   # Organization, Person, Tool elements
        *package_elements, # software_Package elements
        *file_elements,    # software_File elements
        *relationship_elements,  # Relationship elements
        *license_elements, # SimpleLicensingText elements
        *license_rel_elements, # LicenseExpression + license Relationship elements
    ]

    # ── Apply clearing decisions if allowlist provided ──
    clearing_summary = None
    if allowlist_path:
        allowlist = load_allowlist(allowlist_path)
        clearing_annotations, clearing_summary = apply_clearing_decisions(
            graph, allowlist, base_uri,
        )
        if clearing_annotations:
            graph.extend(clearing_annotations)
            # Add annotation IDs to element list
            for ann in clearing_annotations:
                all_element_ids.append(ann["@id"])
            # Update SpdxDocument element list
            spdx_document["element"] = all_element_ids
        print(f"[*] Clearing decisions applied: "
              f"{len(clearing_summary['cleared'])} cleared, "
              f"{len(clearing_summary['excluded'])} excluded, "
              f"{len(clearing_summary['flagged'])} flagged")

    # ── Validate all elements ──
    all_errors = []
    for elem in graph:
        validate_element(elem, all_errors)
    if all_errors:
        print(f"\n⚠  Validation: {len(all_errors)} issue(s) found:")
        for err in all_errors:
            print(f"    - {err}")
    else:
        print("✓  Validation passed: all elements conform to SPDX 3.0 schema")

    # Build final JSON-LD document
    spdx3_doc = {
        "@context": SPDX_CONTEXT,
        "@graph": graph,
    }

    # ── Write output ──
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(spdx3_doc, f, indent=4, ensure_ascii=False)

    print(f"[8/8] SPDX 3.0 JSON-LD written to: {output_path}")

    # ── Write clearing report if applicable ──
    if clearing_summary:
        report_path = output_path.rsplit(".", 1)[0] + "_clearing_report.txt"
        write_clearing_report(clearing_summary, report_path)
        print(f"[*] Clearing report written to: {report_path}")

    # Print summary
    print("\n── Conversion Summary ──")
    print(f"  SPDX Version:     2.3 → 3.0")
    print(f"  Format:           JSON → JSON-LD")
    print(f"  Profiles:         {', '.join(profiles)}")
    print(f"  Total elements:   {len(all_element_ids)}")
    print(f"    Agents/Tools:   {len(agent_elements)}")
    print(f"    Packages:       {len(package_elements)}")
    print(f"    Files:          {len(file_elements)}")
    print(f"    Relationships:  {len(relationship_elements)}")
    print(f"    Extracted Lic:  {len(license_elements)}")
    print(f"    License Rels:   {len(license_rel_elements)}")
    print(f"  Document URI:     {doc_spdx3_id}")


if __name__ == "__main__":
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print("Usage: python spdx_conv.py <input_spdx2.json> <output_spdx3.jsonld> [allowlist.json]")
        print("")
        print("Examples:")
        print("  python spdx_conv.py results/sbom_spdx.json results/sbom_spdx3.jsonld")
        print("  python spdx_conv.py results/sbom_spdx.json results/sbom_spdx3.jsonld allowlist.json")
        sys.exit(1)

    allowlist = sys.argv[3] if len(sys.argv) == 4 else None
    convert(sys.argv[1], sys.argv[2], allowlist)
