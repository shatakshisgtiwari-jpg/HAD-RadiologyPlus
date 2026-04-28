#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Contributors
# SPDX-License-Identifier: MIT

"""FOSSology SPDX 3.0 Scanner."""

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

SCANNERS = {
    'copyright': '/bin/copyright',
    'nomos': '/bin/nomossa',
    'ojo': '/bin/ojo',
    'keyword': '/bin/keyword',
}

SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv'}


# ─────────────────────────────────────────────────────────────
# Run a C scanner binary
# ─────────────────────────────────────────────────────────────

def run_scanner(scanner_path: str, dir_to_scan: str,
                extra_args: list[str] | None = None) -> dict:
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
    findings: dict[str, dict] = {}

    if 'copyright' in scanners:
        raw = run_scanner(SCANNERS['copyright'], dir_to_scan)
        for entry in _get_results_list(raw):
            path = _normalize_path(entry.get('file', ''), dir_to_scan)
            if not path:
                continue
            if path not in findings:
                findings[path] = {"licenses": [], "copyrights": [], "checksums": {}}

            for finding in (entry.get('results') or []):
                if finding is None:
                    continue
                if finding.get('type') == 'statement' and finding.get('content'):
                    text = finding['content'].strip()
                    if text and text not in findings[path]["copyrights"]:
                        findings[path]["copyrights"].append(text)

    if 'nomos' in scanners:
        logging.info("Scanning for licenses (nomos)...")
        extra = ["-S", "-l", "-n", str(max(1, multiprocessing.cpu_count() - 1))]
        raw = run_scanner(SCANNERS['nomos'], dir_to_scan, extra)
        _collect_licenses(raw, findings, dir_to_scan)

    if 'ojo' in scanners:
        logging.info("Scanning for licenses (ojo)...")
        raw = run_scanner(SCANNERS['ojo'], dir_to_scan)
        _collect_licenses(raw, findings, dir_to_scan)

    if 'keyword' in scanners:
        logging.info("Scanning for keywords...")
        raw = run_scanner(SCANNERS['keyword'], dir_to_scan)
        for entry in _get_results_list(raw):
            path = _normalize_path(entry.get('file', ''), dir_to_scan)
            if not path:
                continue
            if path not in findings:
                findings[path] = {"licenses": [], "copyrights": [], "checksums": {}}
            for finding in (entry.get('results') or []):
                if finding and finding.get('content'):
                    text = f"[keyword] {finding['content'].strip()}"
                    if text not in findings[path]["copyrights"]:
                        findings[path]["copyrights"].append(text)

    return findings


def _get_results_list(raw) -> list:
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        return raw.get('results', [])
    return []


def _collect_licenses(raw, findings: dict, dir_to_scan: str) -> None:
    for entry in _get_results_list(raw):
        path = _normalize_path(entry.get('file', ''), dir_to_scan)
        if not path:
            continue
        if path not in findings:
            findings[path] = {"licenses": [], "copyrights": [], "checksums": {}}

        for finding in (entry.get('licenses') or []):
            if finding is None:
                continue
            lic = finding.get('license', '').strip()
            if lic and lic != 'No_license_found' and lic not in findings[path]["licenses"]:
                findings[path]["licenses"].append(lic)


def _normalize_path(path: str, dir_to_scan: str) -> str:
    if not path:
        return ''
    prefix = dir_to_scan if dir_to_scan.endswith('/') else dir_to_scan + '/'
    if path.startswith(prefix):
        rel = path[len(prefix):]
    elif path.startswith('./'):
        rel = path[2:]
    else:
        rel = path

    top = rel.split('/')[0]
    if top in SKIP_DIRS:
        return ''

    return rel


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def main(args: argparse.Namespace) -> int:
    dir_to_scan = args.scan_dir

    scanners_to_run = []
    for s in (args.scanners or ['copyright']):
        s = s.strip().lower()
        if s in SCANNERS:
            scanners_to_run.append(s)

    if not scanners_to_run:
        scanners_to_run = ['copyright']

    logging.info(f"Scanners: {', '.join(scanners_to_run)}")
    logging.info(f"Directory: {dir_to_scan}")

    findings = collect_findings(scanners_to_run, dir_to_scan)

    cr_count = sum(len(f["copyrights"]) for f in findings.values())
    lic_count = sum(len(f["licenses"]) for f in findings.values())
    logging.info(f"Collected {cr_count} (C) and {lic_count} license(s) across {len(findings)} file(s)")

    output_path = args.output
    output_dir = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(output_dir, exist_ok=True)

    findings_path = os.path.join(output_dir, 'findings.json')
    with open(findings_path, 'w', encoding='utf-8') as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)
    logging.info(f"Raw scan findings written to {findings_path}")

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
        description="SPDX 3.0 Scanner",
    )

    parser.add_argument(
        "scanners", type=str, nargs='*', default=['copyright'],
        help="Scanners to run (default: copyright)",
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
