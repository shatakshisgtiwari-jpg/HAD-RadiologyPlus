#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Contributors
# SPDX-License-Identifier: MIT

"""
SPDX 3.0 Report Builder

Generates SPDX 3.0 JSON-LD directly from raw data sources:
  1. FOSSology scanner findings (in-memory or TEXT report)
  2. Built-in package manifest parsers (npm, Maven)
  3. Filesystem walk with checksums and MIME types

Builds SPDX 3.0 elements directly from merged data.

Usage:
    python spdx3_builder.py --repo-root . --fossology-report results/ \\
        --output results/spdx3_report.jsonld
"""

import argparse
import fnmatch
import hashlib
import json
import mimetypes
import os
import re
import sys
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path


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

# Default exclusions for filesystem walk (always skip these)
DEFAULT_EXCLUDES = [
    ".git/**", "node_modules/**", "__pycache__/**", "*.pyc",
    ".DS_Store", "target/**", "build/**", "dist/**", ".gradle/**",
]

# Map MIME type prefixes to SPDX purposes
MIME_TO_PURPOSE = {
    "text/": "source",
    "image/": "data",
    "application/javascript": "source",
    "application/json": "source",
    "application/xml": "source",
    "application/java-archive": "archive",
    "application/zip": "archive",
    "application/gzip": "archive",
    "application/pdf": "documentation",
    "application/octet-stream": "file",
}


# ═════════════════════════════════════════════════════════════════════
# Phase 1: Data Collection
# ═════════════════════════════════════════════════════════════════════

def extract_copyrights_from_text(report_path: str) -> dict[str, dict]:
    """Extract per-file findings from FOSSology agent TEXT output.

    Parses the .txt produced by the FOSSology agent.
    Format:
        Following ... found:
        File: path/to/file
        ...
        \tfinding text at line N
        \tanother finding at line N
        File: next/file
        ...

    Returns: {
        "path/to/file": {
            "licenses": [],
            "copyrights": ["(C) 2026 Author"],
            "checksums": {},
        }
    }
    """
    with open(report_path, "r", encoding="utf-8", errors="replace") as f:
        lines = f.readlines()

    findings: dict[str, dict] = {}
    current_file = None

    # Pattern: "File: path/to/file"
    file_header_re = re.compile(r"^File:\s+(.+)$")
    # Pattern: "\tfinding text at line N" or "\tfinding text at lines N, M"
    finding_re = re.compile(r"^\t(.+?)\s+at\s+lines?\s+[\d,\s]+$")

    for line in lines:
        raw = line.rstrip("\n\r")

        # Check for file header
        m = file_header_re.match(raw)
        if m:
            current_file = m.group(1).strip()
            current_file = re.sub(r"^(\./|/opt/repo/)", "", current_file)
            if current_file not in findings:
                findings[current_file] = {"licenses": [], "copyrights": [], "checksums": {}}
            continue

        # Check for finding (tab-indented line)
        if current_file and raw.startswith("\t"):
            m = finding_re.match(raw)
            if m:
                finding = m.group(1).strip()
            else:
                # Some lines may not have "at line N" suffix
                finding = raw.strip()

            if finding and finding not in ("Copyrights:", "Copyright:", "Following copyrights found:"):
                findings[current_file]["copyrights"].append(finding)
            continue

        # Skip header lines

    # Remove entries with no actual findings
    return {k: v for k, v in findings.items() if v["copyrights"]}


def collect_fossology_findings(report_dir: str) -> dict[str, dict]:
    """Extract per-file findings from FOSSology agent TEXT output."""
    if not os.path.isdir(report_dir):
        print(f"  [!] Report directory not found: {report_dir}")
        return {}

    # Look for agent TEXT output
    txt_files = sorted(Path(report_dir).glob("*.txt"))
    for tf in txt_files:
        try:
            findings = extract_copyrights_from_text(str(tf))
            if findings:
                print(f"  Parsed agent output: {tf.name} ({len(findings)} files)")
                return findings
        except Exception as e:
            print(f"  [!] Failed to parse {tf.name}: {e}")

    print("  [!] No FOSSology report found or parseable")
    return {}


def parse_npm_lockfile(lock_path: str) -> list[dict]:
    """Parse npm package-lock.json (v2/v3) for package data.

    Extracts: name, version, resolved URL, integrity hash, license, dependencies.
    """
    with open(lock_path, "r", encoding="utf-8") as f:
        lock = json.load(f)

    packages = []
    lock_version = lock.get("lockfileVersion", 1)

    if lock_version >= 2 and "packages" in lock:
        # lockfileVersion 2 or 3: packages under "packages" key
        for pkg_path, pkg_data in lock.get("packages", {}).items():
            if not pkg_path:
                continue  # Skip root package entry ""

            # Extract package name from path: "node_modules/@babel/core" → "@babel/core"
            name = pkg_path
            if "node_modules/" in name:
                name = name.split("node_modules/")[-1]

            version = pkg_data.get("version", "")
            if not name or not version:
                continue

            # Normalize license: may be a string or dict {"type": "MIT", ...}
            raw_license = pkg_data.get("license", "")
            if isinstance(raw_license, dict):
                raw_license = raw_license.get("type", "")
            elif not isinstance(raw_license, str):
                raw_license = ""

            pkg = {
                "name": name,
                "version": version,
                "ecosystem": "npm",
                "purl": f"pkg:npm/{name.replace('@', '%40', 1)}@{version}" if name.startswith("@")
                        else f"pkg:npm/{name}@{version}",
                "download_url": pkg_data.get("resolved", ""),
                "integrity": pkg_data.get("integrity", ""),
                "license": raw_license,
                "dependencies": list(pkg_data.get("dependencies", {}).keys()),
                "source_manifest": lock_path,
            }
            packages.append(pkg)

    elif "dependencies" in lock:
        # lockfileVersion 1: flat dependencies object
        def _walk_deps_v1(deps: dict, result: list):
            for name, info in deps.items():
                version = info.get("version", "")
                if not version:
                    continue
                result.append({
                    "name": name,
                    "version": version,
                    "ecosystem": "npm",
                    "purl": f"pkg:npm/{name.replace('@', '%40', 1)}@{version}" if name.startswith("@")
                            else f"pkg:npm/{name}@{version}",
                    "download_url": info.get("resolved", ""),
                    "integrity": info.get("integrity", ""),
                    "license": "",
                    "dependencies": list(info.get("requires", {}).keys()),
                    "source_manifest": lock_path,
                })
                # Recurse into nested dependencies
                if "dependencies" in info:
                    _walk_deps_v1(info["dependencies"], result)

        _walk_deps_v1(lock["dependencies"], packages)

    return packages


def enrich_npm_licenses_from_node_modules(packages: list[dict], lock_dir: str) -> int:
    """Enrich npm package license data from node_modules/*/package.json.

    npm lockfiles (especially older npm versions) often omit the license field.
    If node_modules/ exists (e.g. after 'npm ci'), read each package's own
    package.json for its declared license. Fully project-agnostic.

    Returns the number of packages enriched.
    """
    nm_dir = os.path.join(lock_dir, "node_modules")
    if not os.path.isdir(nm_dir):
        return 0

    enriched = 0
    for pkg in packages:
        if pkg.get("ecosystem") != "npm":
            continue
        if pkg.get("license"):
            continue  # Already has license, don't overwrite

        # Resolve package.json path: node_modules/<name>/package.json
        # Scoped packages: node_modules/@scope/name/package.json
        pkg_json_path = os.path.join(nm_dir, pkg["name"], "package.json")
        if not os.path.isfile(pkg_json_path):
            continue

        try:
            with open(pkg_json_path, "r", encoding="utf-8") as f:
                pkg_meta = json.load(f)

            raw_license = pkg_meta.get("license", "")
            # Handle dict format: {"type": "MIT", "url": "..."}
            if isinstance(raw_license, dict):
                raw_license = raw_license.get("type", "")
            elif not isinstance(raw_license, str):
                raw_license = ""

            # Fallback: deprecated "licenses" array: [{"type":"MIT"}, ...]
            if not raw_license:
                licenses_arr = pkg_meta.get("licenses", [])
                if isinstance(licenses_arr, list) and licenses_arr:
                    parts = []
                    for lic in licenses_arr:
                        if isinstance(lic, dict) and lic.get("type"):
                            parts.append(lic["type"])
                        elif isinstance(lic, str):
                            parts.append(lic)
                    raw_license = " OR ".join(parts) if parts else ""

            if raw_license and raw_license not in ("UNLICENSED",):
                pkg["license"] = raw_license
                enriched += 1
        except (json.JSONDecodeError, OSError, KeyError):
            continue

    return enriched


def parse_pom_xml(pom_path: str) -> list[dict]:
    """Parse Maven pom.xml for declared dependencies.

    Extracts groupId, artifactId, version. Generates Maven PURLs.
    Note: only parses declared deps, not transitive (would need mvn CLI).
    """
    tree = ET.parse(pom_path)
    root = tree.getroot()

    # Handle Maven namespace
    ns_match = re.match(r"\{(.+)\}", root.tag)
    ns = {"m": ns_match.group(1)} if ns_match else {}
    prefix = "m:" if ns else ""

    packages = []
    deps_xpath = f".//{prefix}dependencies/{prefix}dependency"

    for dep in root.findall(deps_xpath, ns):
        group = dep.findtext(f"{prefix}groupId", "", ns).strip()
        artifact = dep.findtext(f"{prefix}artifactId", "", ns).strip()
        version = dep.findtext(f"{prefix}version", "", ns).strip()

        if not artifact:
            continue

        # Clean Maven property references like ${spring.version}
        if version.startswith("${"):
            version = ""

        name = f"{group}:{artifact}" if group else artifact
        purl = f"pkg:maven/{group}/{artifact}@{version}" if group and version else ""

        packages.append({
            "name": name,
            "version": version,
            "ecosystem": "maven",
            "purl": purl,
            "download_url": "",
            "integrity": "",
            "license": "",
            "dependencies": [],
            "source_manifest": pom_path,
        })

    return packages


def detect_and_parse_manifests(repo_root: str) -> list[dict]:
    """Auto-detect package manifests in the repo and parse them.

    Uses built-in parsers for npm (package-lock.json) and Maven (pom.xml).
    Project-independent: detects whatever manifests exist.
    """
    all_packages = []

    # ── Built-in parsers (npm + Maven) ──
    if True:
        for dirpath, dirnames, filenames in os.walk(repo_root):
            # Skip excluded directories
            rel_dir = os.path.relpath(dirpath, repo_root)
            if any(part.startswith(".") or part in ("node_modules", "target", "build", "dist", "__pycache__")
                   for part in Path(rel_dir).parts):
                dirnames.clear()
                continue

            for fname in filenames:
                full_path = os.path.join(dirpath, fname)
                rel_path = os.path.relpath(full_path, repo_root)

                if fname == "package-lock.json":
                    try:
                        pkgs = parse_npm_lockfile(full_path)
                        # Enrich licenses from node_modules if available
                        enriched = enrich_npm_licenses_from_node_modules(pkgs, dirpath)
                        # Normalize manifest path for cross-referencing with findings
                        norm_rel = rel_path.replace("\\", "/")
                        for p in pkgs:
                            p["source_manifest"] = norm_rel
                        lic_note = f" ({enriched} licenses from node_modules)" if enriched else ""
                        print(f"  Parsed {rel_path}: {len(pkgs)} packages{lic_note}")
                        all_packages.extend(pkgs)
                    except Exception as e:
                        print(f"  [!] Failed to parse {rel_path}: {e}")

                elif fname == "pom.xml":
                    try:
                        pkgs = parse_pom_xml(full_path)
                        norm_rel = rel_path.replace("\\", "/")
                        for p in pkgs:
                            p["source_manifest"] = norm_rel
                        print(f"  Parsed {rel_path}: {len(pkgs)} packages")
                        all_packages.extend(pkgs)
                    except Exception as e:
                        print(f"  [!] Failed to parse {rel_path}: {e}")

    return all_packages


def _match_any_pattern(path: str, patterns: list[str]) -> bool:
    """Check if a path matches any fnmatch pattern.

    Normalizes separators to '/' for cross-platform compatibility.
    Handles three pattern forms:
      - "dirname/**"  → match if dirname is any path component
      - "**/*.ext"    → match against full normalized path
      - "*.ext"       → match against filename only
    """
    normalized = path.replace("\\", "/")
    basename = normalized.rstrip("/").rsplit("/", 1)[-1] if normalized else ""
    parts = [p for p in normalized.split("/") if p]

    for pattern in patterns:
        pat = pattern.replace("\\", "/")

        # Pattern like "node_modules/**" or ".git/**": check if the prefix
        # appears as any component of the path
        if pat.endswith("/**"):
            dir_name = pat[:-3]  # strip "/**"
            if dir_name and not dir_name.startswith("*"):
                if dir_name in parts:
                    return True
                continue

        # Full path match (handles "**/*.ext" patterns)
        if fnmatch.fnmatch(normalized, pat):
            return True

        # Filename-only match (handles "*.pyc", ".DS_Store" etc.)
        if basename and fnmatch.fnmatch(basename, pat):
            return True

    return False


def walk_filesystem(repo_root: str, exclude_patterns: list[str]) -> list[dict]:
    """Walk repository, compute SHA-256 for every file, detect MIME types.

    Provides COMPLETE file inventory — every file gets tracked,
    not just files with scanner findings.
    """
    all_excludes = DEFAULT_EXCLUDES + exclude_patterns
    files = []

    for dirpath, dirnames, filenames in os.walk(repo_root):
        rel_dir = os.path.relpath(dirpath, repo_root)
        if rel_dir == ".":
            rel_dir = ""

        # Skip excluded directories
        if rel_dir and _match_any_pattern(rel_dir + "/", all_excludes):
            dirnames.clear()
            continue

        # Prune excluded subdirs to prevent descent
        dirnames[:] = [
            d for d in dirnames
            if not _match_any_pattern(
                os.path.join(rel_dir, d) + "/" if rel_dir else d + "/",
                all_excludes,
            )
        ]

        for fname in filenames:
            rel_path = os.path.join(rel_dir, fname) if rel_dir else fname
            rel_path = rel_path.replace("\\", "/")

            if _match_any_pattern(rel_path, all_excludes):
                continue

            full_path = os.path.join(dirpath, fname)

            # Compute SHA-256
            try:
                sha256 = hashlib.sha256(Path(full_path).read_bytes()).hexdigest()
            except (OSError, PermissionError):
                sha256 = ""

            # Detect MIME type
            mime, _ = mimetypes.guess_type(fname)
            if not mime:
                mime = "application/octet-stream"

            # Map MIME to purpose
            purpose = "other"
            for prefix, p in MIME_TO_PURPOSE.items():
                if mime.startswith(prefix):
                    purpose = p
                    break

            files.append({
                "path": rel_path,
                "sha256": sha256,
                "mime_type": mime,
                "purpose": purpose,
                "licenses": [],
                "copyrights": [],
            })

    return files


def merge_data(
    findings: dict[str, dict],
    packages: list[dict],
    files: list[dict],
) -> tuple[list[dict], list[dict]]:
    """Merge FOSSology findings into file inventory and package data.

    For each file: attach license and (C) data from FOSSology findings.
    For each package: if FOSSology found a license in a manifest file
    belonging to this package, attach it.
    """
    # Merge FOSSology findings into file inventory
    merged_files = 0
    for file_entry in files:
        path = file_entry["path"]
        if path in findings:
            f = findings[path]
            file_entry["licenses"] = f.get("licenses", [])
            file_entry["copyrights"] = f.get("copyrights", [])
            # Use FOSSology checksums if we don't have them
            if not file_entry.get("sha256") and f.get("checksums", {}).get("sha256"):
                file_entry["sha256"] = f["checksums"]["sha256"]
            merged_files += 1

    # For packages without a license from lock file,
    # check if FOSSology found one in a related manifest
    for pkg in packages:
        if pkg.get("license"):
            continue  # Already has license from lock file
        # Check if FOSSology scanned a file matching this package name
        manifest = pkg.get("source_manifest", "")
        if manifest in findings and findings[manifest].get("licenses"):
            pkg["license"] = findings[manifest]["licenses"][0]

    print(f"  Merged FOSSology findings into {merged_files} files")
    return packages, files


# ═════════════════════════════════════════════════════════════════════
# Phase 2: Build SPDX 3.0 Elements
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


def build_package_elements(
    packages: list[dict], base_uri: str, lic_counter: list[int],
) -> tuple[list[dict], list[dict]]:
    """Build software_Package + LicenseExpression + Relationship elements."""
    pkg_elements = []
    lic_elements = []
    seen_names = set()

    for pkg in packages:
        name = pkg["name"]
        # Deduplicate packages by name+version
        dedup_key = f"{name}@{pkg.get('version', '')}"
        if dedup_key in seen_names:
            continue
        seen_names.add(dedup_key)

        safe_name = re.sub(r"[^a-zA-Z0-9._-]", "-", name)
        version_slug = re.sub(r"[^a-zA-Z0-9._-]", "-", pkg.get("version", ""))
        pkg_id = f"{base_uri}/Package/{safe_name}-{version_slug}" if version_slug else f"{base_uri}/Package/{safe_name}"

        elem = {
            "@type": "software_Package",
            "@id": pkg_id,
            "creationInfo": "_:creationinfo",
            "name": name,
        }

        if pkg.get("version"):
            elem["software_packageVersion"] = pkg["version"]
        if pkg.get("download_url"):
            elem["software_downloadLocation"] = pkg["download_url"]

        # Integrity hash from lock file
        hashes = []
        integrity = pkg.get("integrity", "")
        if integrity.startswith("sha512-"):
            hashes.append({"@type": "Hash", "algorithm": "sha512",
                           "hashValue": integrity[len("sha512-"):]})
        elif integrity.startswith("sha256-"):
            hashes.append({"@type": "Hash", "algorithm": "sha256",
                           "hashValue": integrity[len("sha256-"):]})
        if hashes:
            elem["verifiedUsing"] = hashes

        # PURL external identifier
        if pkg.get("purl"):
            elem["externalIdentifier"] = [{
                "@type": "ExternalIdentifier",
                "externalIdentifierType": "purl",
                "identifier": pkg["purl"],
            }]

        # Purpose based on ecosystem
        ecosystem = pkg.get("ecosystem", "")
        if ecosystem in ("npm", "maven", "pypi", "golang", "cargo",
                         "composer", "gem", "nuget", "java-archive"):
            elem["software_primaryPurpose"] = "library"
        elif ecosystem == "github-action":
            elem["software_primaryPurpose"] = "application"

        pkg_elements.append(elem)

        # License → LicenseExpression element + hasDeclaredLicense Relationship
        lic_str = pkg.get("license", "")
        if lic_str and lic_str not in ("NOASSERTION", "NONE", "UNLICENSED"):
            lic_el, rel_el = _make_license_elements(
                pkg_id, lic_str, "hasDeclaredLicense", base_uri, lic_counter,
            )
            lic_elements.extend([lic_el, rel_el])

    return pkg_elements, lic_elements


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
    packages: list[dict], files: list[dict], pkg_elements: list[dict],
    doc_id: str, root_pkg_ids: list[str], base_uri: str,
) -> list[dict]:
    """Build describes, contains, and dependsOn relationships."""
    rels = []
    idx = 0

    # SpdxDocument → describes → root packages
    for root_id in root_pkg_ids:
        rels.append({
            "@type": "Relationship",
            "@id": f"{base_uri}/Relationship/{idx}",
            "creationInfo": "_:creationinfo",
            "from": doc_id,
            "to": [root_id],
            "relationshipType": "describes",
        })
        idx += 1

    # Build a package name → element ID map
    pkg_id_map = {}
    for pe in pkg_elements:
        pkg_id_map[pe["name"]] = pe["@id"]

    # Package → contains → files (assign files to first root package)
    if root_pkg_ids:
        root_id = root_pkg_ids[0]
        for f in files:
            fid = f.get("_element_id")
            if fid:
                rels.append({
                    "@type": "Relationship",
                    "@id": f"{base_uri}/Relationship/{idx}",
                    "creationInfo": "_:creationinfo",
                    "from": root_id,
                    "to": [fid],
                    "relationshipType": "contains",
                })
                idx += 1

    # Package → dependsOn → dependency packages
    for pkg in packages:
        from_id = pkg_id_map.get(pkg["name"])
        if not from_id:
            continue
        for dep_name in pkg.get("dependencies", []):
            to_id = pkg_id_map.get(dep_name)
            if to_id:
                rels.append({
                    "@type": "Relationship",
                    "@id": f"{base_uri}/Relationship/{idx}",
                    "creationInfo": "_:creationinfo",
                    "from": from_id,
                    "to": [to_id],
                    "relationshipType": "dependsOn",
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
) -> None:
    """Main orchestrator: collect → build → validate → write.

    Args:
        repo_root: Path to repository root directory.
        report_dir: Path to directory containing FOSSology report files.
        output_path: Output path for SPDX 3.0 JSON-LD file.
        findings_override: If provided, use these findings directly instead
            of parsing report files. Dict mapping file paths to
            {"licenses": [...], "copyrights": [...], "checksums": {}}.
    """

    repo_root = os.path.abspath(repo_root)
    doc_name = os.environ.get("GITHUB_REPOSITORY", os.path.basename(repo_root))

    print(f"\n{'='*60}")
    print(f"SPDX 3.0 Direct Builder")
    print(f"{'='*60}\n")

    # ── Phase 1: Collect Data ──
    print("[Phase 1] Collecting data from all sources...\n")

    # 1.1 FOSSology findings
    print("  [1.1] FOSSology scan findings:")
    if findings_override is not None:
        findings = findings_override
        print(f"  Using {len(findings)} file(s) from direct scanner input")
    elif report_dir:
        findings = collect_fossology_findings(report_dir)
    else:
        findings = {}
        print("  [!] No report directory specified, skipping FOSSology data")

    # 1.2 Package manifests
    print(f"\n  [1.2] Package manifest detection:")
    packages = detect_and_parse_manifests(repo_root)
    print(f"  Total packages detected: {len(packages)}")

    # 1.3 Filesystem walk
    print(f"\n  [1.3] Filesystem walk:")
    output_dir = os.path.relpath(os.path.dirname(os.path.abspath(output_path)), repo_root)
    auto_excludes = []
    if not output_dir.startswith(".."):
        auto_excludes.append(output_dir.replace("\\", "/") + "/**")
    files = walk_filesystem(repo_root, auto_excludes)
    print(f"  Total files inventoried: {len(files)}")

    # 1.4 Merge FOSSology findings into file/package inventory
    print(f"\n  [1.4] Merging data sources:")
    packages, files = merge_data(findings, packages, files)

    # Count enrichment stats
    files_with_license = sum(1 for f in files if f.get("licenses"))
    files_with_copyright = sum(1 for f in files if f.get("copyrights"))
    print(f"  Files with license data: {files_with_license}")
    print(f"  Files with (C) data: {files_with_copyright}")

    # ── Phase 2: Build SPDX 3.0 Elements ──
    print(f"\n[Phase 2] Building SPDX 3.0 elements...\n")

    base_uri = generate_base_uri(doc_name)
    doc_id = f"{base_uri}/Document"
    lic_counter = [0]

    # 2.1 CreationInfo + Agents
    creation_info, agent_elements = build_creation_info(base_uri)
    print(f"  [2.1] CreationInfo: {len(agent_elements)} agent/tool elements")

    # 2.2 Packages
    pkg_elements, pkg_lic_elements = build_package_elements(packages, base_uri, lic_counter)
    print(f"  [2.2] Packages: {len(pkg_elements)} elements, {len(pkg_lic_elements)} license elements")

    # 2.3 Files
    file_elements, file_lic_elements = build_file_elements(files, base_uri, lic_counter)
    print(f"  [2.3] Files: {len(file_elements)} elements, {len(file_lic_elements)} license elements")

    # 2.4 Determine root package
    # Create a synthetic root package representing the repository itself
    root_pkg_id = f"{base_uri}/Package/{re.sub(r'[^a-zA-Z0-9._-]', '-', doc_name)}"
    root_pkg = {
        "@type": "software_Package",
        "@id": root_pkg_id,
        "creationInfo": "_:creationinfo",
        "name": doc_name,
        "software_primaryPurpose": "application",
    }
    pkg_elements.insert(0, root_pkg)

    # 2.5 Structural relationships
    rel_elements = build_structural_relationships(
        packages, files, pkg_elements, doc_id, [root_pkg_id], base_uri,
    )
    print(f"  [2.4] Relationships: {len(rel_elements)} elements")

    # 2.6 Collect all element IDs
    all_elements = (
        agent_elements + pkg_elements + file_elements +
        rel_elements + pkg_lic_elements + file_lic_elements
    )
    all_element_ids = [e["@id"] for e in all_elements]

    # Determine profiles
    profiles = ["core", "software"]
    if pkg_lic_elements or file_lic_elements:
        profiles.append("licensing")

    # Build SpdxDocument
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

    # Assemble @graph
    graph = [creation_info, spdx_document] + all_elements

    # ── Phase 3: Validation ──
    print(f"\n[Phase 3] Validation...\n")

    # Validate
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

    # ── Phase 4: Serialize & Output ──
    print(f"\n[Phase 4] Serializing output...\n")

    spdx3_doc = {"@context": SPDX_CONTEXT, "@graph": graph}

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(spdx3_doc, f, indent=4, ensure_ascii=False)
    print(f"  SPDX 3.0 JSON-LD written to: {output_path}")

    # Summary
    print(f"\n{'='*60}")
    print(f"  Build Summary")
    print(f"{'='*60}")
    print(f"  Profiles:        {', '.join(profiles)}")
    print(f"  Total elements:  {len(all_element_ids)}")
    print(f"    Agents/Tools:  {len(agent_elements)}")
    print(f"    Packages:      {len(pkg_elements)}")
    print(f"    Files:         {len(file_elements)}")
    print(f"    Relationships: {len(rel_elements)}")
    print(f"    License Elems: {len(pkg_lic_elements) + len(file_lic_elements)}")
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
