#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Contributors
# SPDX-License-Identifier: MIT

"""
FOSSology SPDX 3.0 Scanner — no FoScanner dependency.

Calls the C scanner binaries directly via subprocess, collects their
JSON output (-J flag), saves raw findings to findings.json, then feeds
them to spdx3_builder to produce SPDX 3.0 JSON-LD.

    C binaries (subprocess -J) → JSON stdout → findings.json → SPDX 3.0

No FoScanner library. No SPDX 2.x at any stage.
"""

import argparse
import json
import logging
import multiprocessing
import os
import sys
from subprocess import Popen, PIPE

# SPDX 3.0 builder
sys.path.insert(0, '/opt')
import spdx3_builder

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# Scanner binary paths (from the base fossology/fossology:scanner image)
SCANNERS = {
    'copyright': '/bin/copyright',
    'nomos': '/bin/nomossa',
    'ojo': '/bin/ojo',
    'keyword': '/bin/keyword',
}


# ─────────────────────────────────────────────────────────────
# Run a C scanner binary
# ─────────────────────────────────────────────────────────────

def run_scanner(scanner_path: str, dir_to_scan: str,
                extra_args: list[str] | None = None) -> dict:
    """Run a FOSSology C scanner binary with -J (JSON output) and -d (directory).

    Returns the parsed JSON dict from the scanner's stdout.
    """
    command = [scanner_path, "-J", "-d", dir_to_scan]
    if extra_args:
        command.extend(extra_args)

    logging.info(f"Running: {' '.join(command)}")
    process = Popen(command, stdout=PIPE, text=True, encoding='UTF-8')
    stdout, _ = process.communicate()

    if process.returncode != 0:
        logging.error(f"{scanner_path} exited with code {process.returncode}")
        return {}

    if not stdout.strip():
        return {}

    return json.loads(stdout.strip())


# ─────────────────────────────────────────────────────────────
# Collect findings from scanner JSON output
# ─────────────────────────────────────────────────────────────

def collect_findings(scanners: list[str], dir_to_scan: str) -> dict:
    """Run selected scanners and collect per-file findings from their JSON output.

    The C binaries with -J output JSON like:
      {"results": [{"file": "path", "results": [{"content": "...", "type": "statement"}]}]}
      {"results": [{"file": "path", "licenses": [{"license": "MIT"}]}]}

    Returns:
        {filepath: {"licenses": [...], "copyrights": [...], "checksums": {}}}
    """
    findings: dict[str, dict] = {}

    # ── Copyright scanner ──
    if 'copyright' in scanners:
        logging.info("Scanning for copyrights...")
        raw = run_scanner(SCANNERS['copyright'], dir_to_scan)
        for entry in raw.get('results', []):
            path = _normalize_path(entry.get('file', ''), dir_to_scan)
            if not path:
                continue
            if path not in findings:
                findings[path] = {"licenses": [], "copyrights": [], "checksums": {}}

            for finding in entry.get('results', []):
                if finding is None:
                    continue
                # Only include "statement" type (actual copyright text)
                if finding.get('type') == 'statement' and finding.get('content'):
                    text = finding['content'].strip()
                    if text and text not in findings[path]["copyrights"]:
                        findings[path]["copyrights"].append(text)

    # ── Nomos license scanner ──
    if 'nomos' in scanners:
        logging.info("Scanning for licenses (nomos)...")
        extra = ["-S", "-l", "-n", str(max(1, multiprocessing.cpu_count() - 1))]
        raw = run_scanner(SCANNERS['nomos'], dir_to_scan, extra)
        _collect_licenses(raw, findings, dir_to_scan)

    # ── OJO license scanner ──
    if 'ojo' in scanners:
        logging.info("Scanning for licenses (ojo)...")
        raw = run_scanner(SCANNERS['ojo'], dir_to_scan)
        _collect_licenses(raw, findings, dir_to_scan)

    # ── Keyword scanner ──
    if 'keyword' in scanners:
        logging.info("Scanning for keywords...")
        raw = run_scanner(SCANNERS['keyword'], dir_to_scan)
        # Keywords are informational; store as copyrights for now
        for entry in raw.get('results', []):
            path = _normalize_path(entry.get('file', ''), dir_to_scan)
            if not path:
                continue
            if path not in findings:
                findings[path] = {"licenses": [], "copyrights": [], "checksums": {}}
            for finding in entry.get('results', []):
                if finding and finding.get('content'):
                    text = f"[keyword] {finding['content'].strip()}"
                    if text not in findings[path]["copyrights"]:
                        findings[path]["copyrights"].append(text)

    return findings


def _collect_licenses(raw: dict, findings: dict, dir_to_scan: str) -> None:
    """Extract license findings from nomos/ojo JSON output into findings dict."""
    for entry in raw.get('results', []):
        path = _normalize_path(entry.get('file', ''), dir_to_scan)
        if not path:
            continue
        if path not in findings:
            findings[path] = {"licenses": [], "copyrights": [], "checksums": {}}

        for finding in entry.get('licenses', []):
            if finding is None:
                continue
            lic = finding.get('license', '').strip()
            if lic and lic != 'No_license_found' and lic not in findings[path]["licenses"]:
                findings[path]["licenses"].append(lic)


def _normalize_path(path: str, dir_to_scan: str) -> str:
    """Strip the scan directory prefix from a file path."""
    if not path:
        return ''
    prefix = dir_to_scan if dir_to_scan.endswith('/') else dir_to_scan + '/'
    if path.startswith(prefix):
        return path[len(prefix):]
    if path.startswith('./'):
        return path[2:]
    return path


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def main(args: argparse.Namespace) -> int:
    dir_to_scan = args.scan_dir

    # Determine which scanners to run
    scanners_to_run = []
    for s in (args.scanners or ['copyright']):
        s = s.strip().lower()
        if s in SCANNERS:
            scanners_to_run.append(s)

    if not scanners_to_run:
        scanners_to_run = ['copyright']

    logging.info(f"Scanners: {', '.join(scanners_to_run)}")
    logging.info(f"Directory: {dir_to_scan}")

    # ── Collect findings directly from C binaries ──
    findings = collect_findings(scanners_to_run, dir_to_scan)

    copyright_count = sum(len(f["copyrights"]) for f in findings.values())
    license_count = sum(len(f["licenses"]) for f in findings.values())
    logging.info(
        f"Collected {copyright_count} copyright(s) and {license_count} license(s) "
        f"across {len(findings)} file(s)"
    )

    # ── Write findings to JSON (intermediate artifact for debugging) ──
    output_path = args.output
    output_dir = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(output_dir, exist_ok=True)

    findings_path = os.path.join(output_dir, 'findings.json')
    with open(findings_path, 'w', encoding='utf-8') as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)
    logging.info(f"Raw scan findings written to {findings_path}")

    # ── Build SPDX 3.0 JSON-LD from the saved findings file ──
    spdx3_builder.build(
        repo_root=dir_to_scan,
        report_dir=None,
        output_path=output_path,
        findings_file=findings_path,
    )

    logging.info(f"SPDX 3.0 JSON-LD written to {output_path}")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="FOSSology SPDX 3.0 Scanner — calls C binaries directly, no FoScanner.",
    )

    parser.add_argument(
        "scanners", type=str, nargs='*', default=['copyright'],
        help="Scanners to run: copyright, nomos, ojo, keyword (default: copyright)",
    )

    parser.add_argument(
        "--scan-dir", type=str, default="/opt/repo",
        help="Directory to scan (default: /opt/repo)",
    )

    parser.add_argument(
        "--output", type=str, default="results/spdx3_report.jsonld",
        help="Output path for SPDX 3.0 JSON-LD (default: results/spdx3_report.jsonld)",
    )

    parsed = parser.parse_args()
    sys.exit(main(parsed))
