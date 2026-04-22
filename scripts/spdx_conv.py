#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 HAD-RadiologyPlus Contributors
# SPDX-License-Identifier: MIT

"""
SPDX 2.3 JSON → SPDX 3.0 JSON-LD Converter

Converts FOSSology CI scanner SPDX 2.3 JSON reports to SPDX 3.0 JSON-LD format.
Implements Core, Software, and Licensing profiles.

Usage:
    python spdx2to3.py <input_spdx2.json> <output_spdx3.jsonld>
"""

import json
import sys
import uuid
from datetime import datetime, timezone


# ──────────────────────────────────────────────
# Mapping tables: SPDX 2.3 → SPDX 3.0
# ──────────────────────────────────────────────

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


def generate_base_uri(doc_name: str) -> str:
    """Generate a unique base URI for all elements in this document."""
    unique_id = uuid.uuid4().hex[:12]
    safe_name = doc_name.replace(" ", "-").replace("/", "-")
    return f"https://spdx.org/spdx3/{safe_name}/{unique_id}"


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
            "type": "Organization",
            "spdxId": org_id,
            "creationInfo": "_:creationinfo",
            "name": org["name"],
        }
        if org["email"]:
            org_element["externalIdentifier"] = [{
                "type": "ExternalIdentifier",
                "externalIdentifierType": "email",
                "identifier": org["email"],
            }]
        agent_elements.append(org_element)

    # Create Person elements
    for i, person in enumerate(parsed["persons"]):
        person_id = f"{base_uri}/Agent/Person/{person['name'].replace(' ', '')}"
        created_by_ids.append(person_id)

        person_element = {
            "type": "Person",
            "spdxId": person_id,
            "creationInfo": "_:creationinfo",
            "name": person["name"],
        }
        if person["email"]:
            person_element["externalIdentifier"] = [{
                "type": "ExternalIdentifier",
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
            "type": "Tool",
            "spdxId": tool_id,
            "creationInfo": "_:creationinfo",
            "name": tool["name"],
        }
        agent_elements.append(tool_element)

    # If no tools were listed, add FOSSology CI Scanner as default
    if not created_using_ids:
        default_tool_id = f"{base_uri}/Tool/fossology-ci-scanner"
        created_using_ids.append(default_tool_id)
        agent_elements.append({
            "type": "Tool",
            "spdxId": default_tool_id,
            "creationInfo": "_:creationinfo",
            "name": "FOSSology CI Scanner",
        })

    # If no agents were listed, add FOSSology as default organization
    if not created_by_ids:
        default_org_id = f"{base_uri}/Agent/Organization/FOSSology"
        created_by_ids.append(default_org_id)
        agent_elements.append({
            "type": "Organization",
            "spdxId": default_org_id,
            "creationInfo": "_:creationinfo",
            "name": "FOSSology",
        })

    # Build the CreationInfo object (shared via blank node reference)
    creation_info = {
        "type": "CreationInfo",
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
            "type": "Hash",
            "algorithm": algo,
            "hashValue": cs["checksumValue"],
        })
    return hashes


def convert_package(pkg: dict, base_uri: str, id_map: dict) -> dict:
    """Convert an SPDX 2.3 package to SPDX 3.0 software_Package element."""
    pkg_name = pkg.get("name", "UnknownPackage")
    spdx3_id = f"{base_uri}/Package/{pkg_name}"

    # Store mapping from old ID to new ID
    id_map[pkg["SPDXID"]] = spdx3_id

    pkg3 = {
        "type": "software_Package",
        "spdxId": spdx3_id,
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

    # Package verification code
    pvc = pkg.get("packageVerificationCode", {})
    if pvc and pvc.get("packageVerificationCodeValue"):
        pkg3["software_packageVerificationCode"] = {
            "type": "PackageVerificationCode",
            "algorithm": "sha1",
            "hashValue": pvc["packageVerificationCodeValue"],
        }

    # Checksums → verifiedUsing
    if pkg.get("checksums"):
        pkg3["verifiedUsing"] = convert_checksums(pkg["checksums"])

    # License concluded
    concluded = pkg.get("licenseConcluded")
    if concluded and concluded not in ("NOASSERTION", "NONE"):
        pkg3["software_concludedLicense"] = concluded

    # License declared
    declared = pkg.get("licenseDeclared")
    if declared and declared not in ("NOASSERTION", "NONE"):
        pkg3["software_declaredLicense"] = declared

    # License info from files (aggregate)
    license_info = pkg.get("licenseInfoFromFiles", [])
    if license_info:
        pkg3["software_licenseInfoInFile"] = license_info

    # Files analyzed
    if pkg.get("filesAnalyzed") is not None:
        pkg3["software_filesAnalyzed"] = pkg["filesAnalyzed"]

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
                    "type": "ExternalIdentifier",
                    "externalIdentifierType": "purl",
                    "identifier": ref.get("referenceLocator", ""),
                })
            elif "cpe" in ref_type:
                pkg3["externalIdentifier"].append({
                    "type": "ExternalIdentifier",
                    "externalIdentifierType": "cpe23Type",
                    "identifier": ref.get("referenceLocator", ""),
                })

    return pkg3


def convert_file(file_entry: dict, base_uri: str, id_map: dict) -> dict:
    """Convert an SPDX 2.3 file to SPDX 3.0 software_File element."""
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
        "type": "software_File",
        "spdxId": spdx3_id,
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

    # License concluded
    concluded = file_entry.get("licenseConcluded")
    if concluded and concluded not in ("NOASSERTION", "NONE"):
        file3["software_concludedLicense"] = concluded

    # License info in files (detected licenses)
    license_info = file_entry.get("licenseInfoInFiles", [])
    if license_info:
        file3["software_licenseInfoInFile"] = license_info

    # License comments
    if file_entry.get("licenseComments"):
        file3["comment"] = file_entry["licenseComments"]

    return file3


def convert_relationship(rel: dict, base_uri: str, id_map: dict, index: int) -> dict:
    """Convert an SPDX 2.3 relationship to SPDX 3.0 Relationship element."""
    rel_id = f"{base_uri}/Relationship/{index}"

    from_id = id_map.get(rel["spdxElementId"], rel["spdxElementId"])
    to_id = id_map.get(rel["relatedSpdxElement"], rel["relatedSpdxElement"])
    rel_type = RELATIONSHIP_TYPE_MAP.get(
        rel["relationshipType"], rel["relationshipType"].lower()
    )

    rel3 = {
        "type": "Relationship",
        "spdxId": rel_id,
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
            "type": "simplelicensing_SimpleLicensingText",
            "spdxId": spdx3_id,
            "creationInfo": "_:creationinfo",
            "name": lic.get("name", lic_id),
            "simplelicensing_licenseText": lic.get("extractedText", ""),
        }

        # Cross-references (seeAlso)
        see_also = lic.get("seeAlsos", [])
        if see_also:
            lic3["externalRef"] = [
                {"type": "ExternalRef", "externalRefType": "seeAlso", "locator": [url]}
                for url in see_also
            ]

        if lic.get("comment"):
            lic3["comment"] = lic["comment"]

        elements.append(lic3)

    return elements


def convert(input_path: str, output_path: str) -> None:
    """
    Main conversion: SPDX 2.3 JSON → SPDX 3.0 JSON-LD.

    Implements:
    - Core Profile: SpdxDocument, CreationInfo, Relationship, Agent, Tool
    - Software Profile: Package, File, checksums, purposes
    - Licensing Profile: SimpleLicensingText (extracted licenses)
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
    base_uri = generate_base_uri(doc_name)
    id_map = {}  # Maps SPDX 2.3 SPDXID → SPDX 3.0 spdxId URI

    print(f"[2/8] Base URI: {base_uri}")

    # ── Step 3: Build CreationInfo and Agent/Tool elements ──
    creation_info, agent_elements = build_creation_info(spdx2_doc, base_uri)
    print(f"[3/8] CreationInfo built: {len(agent_elements)} agent/tool elements")

    # ── Step 4: Convert packages ──
    package_elements = []
    for pkg in spdx2_doc.get("packages", []):
        pkg3 = convert_package(pkg, base_uri, id_map)
        package_elements.append(pkg3)
    print(f"[4/8] Converted {len(package_elements)} packages")

    # ── Step 5: Convert files ──
    file_elements = []
    for file_entry in spdx2_doc.get("files", []):
        file3 = convert_file(file_entry, base_uri, id_map)
        file_elements.append(file3)
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
        [e["spdxId"] for e in agent_elements]
        + [e["spdxId"] for e in package_elements]
        + [e["spdxId"] for e in file_elements]
        + [e["spdxId"] for e in relationship_elements]
        + [e["spdxId"] for e in license_elements]
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
    if license_elements:
        profiles.append("licensing")

    # Build the SpdxDocument element
    spdx_document = {
        "type": "SpdxDocument",
        "spdxId": doc_spdx3_id,
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
    ]

    # Build final JSON-LD document
    spdx3_doc = {
        "@context": "https://spdx.org/rdf/3.0.0/spdx-context.jsonld",
        "@graph": graph,
    }

    # ── Write output ──
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(spdx3_doc, f, indent=4, ensure_ascii=False)

    print(f"[8/8] SPDX 3.0 JSON-LD written to: {output_path}")

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
    print(f"    Licenses:       {len(license_elements)}")
    print(f"  Document URI:     {doc_spdx3_id}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python spdx2to3.py <input_spdx2.json> <output_spdx3.jsonld>")
        print("Example: python spdx2to3.py results/sbom_spdx.json results/sbom_spdx3.jsonld")
        sys.exit(1)

    convert(sys.argv[1], sys.argv[2])
