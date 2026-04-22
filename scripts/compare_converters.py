#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 HAD-RadiologyPlus Contributors
# SPDX-License-Identifier: MIT

"""
SPDX 3.0 Converter Comparison — Demo Script

Compares the output of spdx_conv.py (custom) vs spdx_conv_official.py (spdx-tools)
and prints a structured report showing where the official tool falls short.

Usage:
    python scripts/compare_converters.py results/sbom_spdx3_custom.jsonld results/sbom_spdx3_official.jsonld
"""

import json
import sys
from collections import Counter

# ── ANSI colors for terminal output ──
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"
CHECK = f"{GREEN}✓{RESET}"
CROSS = f"{RED}✗{RESET}"
WARN = f"{YELLOW}⚠{RESET}"


def load(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def check_context(doc: dict, label: str) -> list[str]:
    """Check @context quality."""
    findings = []
    ctx = doc.get("@context")
    if ctx is None:
        findings.append(f"{CROSS} No @context — invalid JSON-LD")
    elif isinstance(ctx, str):
        findings.append(f"{WARN} @context is a URL string only (requires network fetch to resolve types)")
    elif isinstance(ctx, list):
        has_url = any(isinstance(c, str) for c in ctx)
        has_inline = any(isinstance(c, dict) for c in ctx)
        if has_url and has_inline:
            inline = [c for c in ctx if isinstance(c, dict)][0]
            findings.append(f"{CHECK} @context is self-contained: URL + {len(inline)} inline term definitions")
        elif has_url:
            findings.append(f"{WARN} @context has URL only, no inline fallback")
        elif has_inline:
            findings.append(f"{CHECK} @context has inline definitions (no URL)")
    return findings


def check_jsonld_keywords(doc: dict, label: str) -> list[str]:
    """Check whether standard JSON-LD keywords @type/@id are used."""
    findings = []
    graph = doc.get("@graph", [])
    uses_at_type = sum(1 for e in graph if "@type" in e)
    uses_type = sum(1 for e in graph if "type" in e and "@type" not in e)
    uses_at_id = sum(1 for e in graph if "@id" in e)
    uses_spdxid = sum(1 for e in graph if "spdxId" in e and "@id" not in e)

    if uses_at_type == len(graph):
        findings.append(f"{CHECK} All {uses_at_type} elements use standard @type keyword")
    elif uses_type > 0:
        findings.append(f"{CROSS} {uses_type}/{len(graph)} elements use non-standard 'type' instead of '@type'")

    if uses_at_id > 0 and uses_spdxid == 0:
        findings.append(f"{CHECK} All identifiable elements use standard @id keyword")
    elif uses_spdxid > 0:
        findings.append(f"{CROSS} {uses_spdxid} elements use non-standard 'spdxId' instead of '@id'")

    return findings


def check_types(doc: dict) -> tuple[Counter, list[str]]:
    """Analyze element types in the graph."""
    graph = doc.get("@graph", [])
    type_key = "@type" if any("@type" in e for e in graph) else "type"
    types = Counter(e.get(type_key, "MISSING") for e in graph)
    findings = []

    # Check for enrichment types
    enriched = {"CreationInfo", "Organization", "Person", "Tool", "SpdxDocument"}
    present = enriched & set(types.keys())
    missing = enriched - set(types.keys())
    if present:
        findings.append(f"{CHECK} Enriched types present: {', '.join(sorted(present))}")
    if missing:
        findings.append(f"{CROSS} Missing enriched types: {', '.join(sorted(missing))}")

    # Check for license-as-relationship pattern
    lic_expr = types.get("simplelicensing_LicenseExpression", 0)
    rels = [e for e in graph if e.get(type_key) == "Relationship"]
    lic_rels = [r for r in rels if r.get("relationshipType") in ("hasDeclaredLicense", "hasConcludedLicense")]
    if lic_expr > 0 and lic_rels:
        findings.append(f"{CHECK} License-as-Relationship pattern: {lic_expr} LicenseExpression + {len(lic_rels)} license rels")
    else:
        findings.append(f"{WARN} No license-as-Relationship pattern (licenses may be inline properties)")

    return types, findings


def check_validation(doc: dict) -> list[str]:
    """Check for structural issues that indicate invalid SPDX 3.0."""
    findings = []
    graph = doc.get("@graph", [])
    type_key = "@type" if any("@type" in e for e in graph) else "type"
    id_key = "@id" if any("@id" in e for e in graph) else "spdxId"

    # Check SpdxDocument has required fields
    spdx_docs = [e for e in graph if e.get(type_key) in ("SpdxDocument",)]
    for sd in spdx_docs:
        if "profileConformance" in sd:
            findings.append(f"{CHECK} SpdxDocument has profileConformance: {sd['profileConformance']}")
        else:
            findings.append(f"{CROSS} SpdxDocument missing profileConformance")
        if "rootElement" in sd:
            findings.append(f"{CHECK} SpdxDocument has rootElement ({len(sd['rootElement'])} entries)")
        else:
            findings.append(f"{CROSS} SpdxDocument missing rootElement")
        if "element" in sd:
            findings.append(f"{CHECK} SpdxDocument has element list ({len(sd['element'])} entries)")
        else:
            findings.append(f"{CROSS} SpdxDocument missing element list")

    # Check CreationInfo is shared blank node
    cis = [e for e in graph if e.get(type_key) == "CreationInfo"]
    if cis:
        ci = cis[0]
        ci_id = ci.get(id_key, ci.get("@id", ""))
        if ci_id.startswith("_:"):
            findings.append(f"{CHECK} CreationInfo is a shared blank node ({ci_id})")
        else:
            findings.append(f"{WARN} CreationInfo is not a blank node (id: {ci_id})")
    else:
        findings.append(f"{CROSS} No CreationInfo element in graph")

    # Check Relationship 'to' is always a list
    rels = [e for e in graph if e.get(type_key) == "Relationship"]
    to_as_list = sum(1 for r in rels if isinstance(r.get("to"), list))
    if rels:
        if to_as_list == len(rels):
            findings.append(f"{CHECK} All {len(rels)} Relationships have 'to' as list")
        else:
            findings.append(f"{CROSS} {len(rels) - to_as_list}/{len(rels)} Relationships have 'to' as non-list")

    # Check for duplicate keys (official tool known issue)
    # Can't detect from parsed JSON, note it
    return findings


def check_non_standard_props(doc: dict) -> list[str]:
    """Check for SPDX 2.3 leftover properties that don't belong in 3.0."""
    findings = []
    graph = doc.get("@graph", [])
    bad_props = {
        "software_concludedLicense": "Should be hasConcludedLicense Relationship",
        "software_declaredLicense": "Should be hasDeclaredLicense Relationship",
        "software_licenseInfoInFile": "Removed in SPDX 3.0",
        "software_filesAnalyzed": "Removed in SPDX 3.0",
        "software_packageVerificationCode": "Removed in 3.0; use Hash in verifiedUsing",
    }
    for elem in graph:
        for prop, reason in bad_props.items():
            if prop in elem:
                eid = elem.get("@id", elem.get("spdxId", "?"))
                findings.append(f"{CROSS} {prop} on {eid} — {reason}")
    if not findings:
        findings.append(f"{CHECK} No non-standard SPDX 2.3 leftover properties")
    return findings


def check_uri_scheme(doc: dict) -> list[str]:
    """Check that @id URIs don't point to non-existent web pages."""
    findings = []
    graph = doc.get("@graph", [])
    id_key = "@id" if any("@id" in e for e in graph) else "spdxId"
    ids = [e.get(id_key, "") for e in graph if e.get(id_key, "").startswith("http")]
    spdx_org = [i for i in ids if "spdx.org/spdx3" in i or "spdx.org/rdf" in i]
    if spdx_org:
        findings.append(f"{CROSS} {len(spdx_org)} @id URIs point to spdx.org (will 404 in browser)")
    else:
        findings.append(f"{CHECK} No @id URIs pointing to non-existent spdx.org paths")
    return findings


def main():
    if len(sys.argv) != 3:
        print("Usage: python compare_converters.py <custom.jsonld> <official.jsonld>")
        sys.exit(1)

    custom_path, official_path = sys.argv[1], sys.argv[2]
    custom = load(custom_path)
    official = load(official_path)

    print(f"\n{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}  SPDX 3.0 Converter Comparison: Custom vs Official (spdx-tools){RESET}")
    print(f"{BOLD}{'='*70}{RESET}\n")

    categories = [
        ("1. @context (self-contained?)", check_context),
        ("2. JSON-LD keywords (@type/@id)", check_jsonld_keywords),
        ("3. Non-standard properties", check_non_standard_props),
        ("4. URI scheme (resolvable?)", check_uri_scheme),
    ]

    custom_score = 0
    official_score = 0

    for title, checker in categories:
        print(f"\n{BOLD}{CYAN}── {title} ──{RESET}")
        c_findings = checker(custom, "Custom")
        o_findings = checker(official, "Official")

        print(f"\n  {BOLD}Custom script:{RESET}")
        for f in c_findings:
            print(f"    {f}")
            if CHECK in f:
                custom_score += 1

        print(f"\n  {BOLD}Official spdx-tools:{RESET}")
        for f in o_findings:
            print(f"    {f}")
            if CHECK in f:
                official_score += 1

    # Type analysis
    print(f"\n{BOLD}{CYAN}── 5. Element types ──{RESET}")
    c_types, c_findings = check_types(custom)
    o_types, o_findings = check_types(official)

    print(f"\n  {BOLD}Custom script:{RESET}")
    for f in c_findings:
        print(f"    {f}")
        if CHECK in f:
            custom_score += 1
    print(f"    Total: {sum(c_types.values())} elements — {dict(c_types)}")

    print(f"\n  {BOLD}Official spdx-tools:{RESET}")
    for f in o_findings:
        print(f"    {f}")
        if CHECK in f:
            official_score += 1
    print(f"    Total: {sum(o_types.values())} elements — {dict(o_types)}")

    # Structural validation
    print(f"\n{BOLD}{CYAN}── 6. SPDX 3.0 structural validation ──{RESET}")
    c_struct = check_validation(custom)
    o_struct = check_validation(official)

    print(f"\n  {BOLD}Custom script:{RESET}")
    for f in c_struct:
        print(f"    {f}")
        if CHECK in f:
            custom_score += 1

    print(f"\n  {BOLD}Official spdx-tools:{RESET}")
    for f in o_struct:
        print(f"    {f}")
        if CHECK in f:
            official_score += 1

    # Final scorecard
    print(f"\n{BOLD}{'='*70}{RESET}")
    print(f"{BOLD}  SCORECARD{RESET}")
    print(f"{BOLD}{'='*70}{RESET}")
    print(f"  Custom script:     {GREEN}{custom_score} checks passed{RESET}")
    print(f"  Official spdx-tools: {'' if official_score >= custom_score else RED}{official_score} checks passed{RESET}")
    if custom_score > official_score:
        print(f"\n  {GREEN}{BOLD}→ Custom script wins by {custom_score - official_score} checks{RESET}")
    elif official_score > custom_score:
        print(f"\n  {GREEN}{BOLD}→ Official spdx-tools wins by {official_score - custom_score} checks{RESET}")
    else:
        print(f"\n  {YELLOW}{BOLD}→ Tie{RESET}")

    print(f"\n{BOLD}Key advantages of custom script:{RESET}")
    print(f"  • Self-contained @context (inline + URL fallback)")
    print(f"  • Standard JSON-LD keywords (@type, @id)")
    print(f"  • License-as-Relationship pattern (SPDX 3.0 spec)")
    print(f"  • No non-standard leftover properties")
    print(f"  • URN-based identifiers (no misleading 404s)")
    print(f"  • Built-in validation during conversion")
    print(f"  • Zero dependencies (stdlib only)")
    print()


if __name__ == "__main__":
    main()
