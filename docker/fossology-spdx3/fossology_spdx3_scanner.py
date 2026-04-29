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
    'keyword': '/bin/keyword',
    'nomos': '/bin/nomossa',
    'ojo': '/bin/ojo',
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
    process = Popen(command, stdout=PIPE, stderr=PIPE, text=True, encoding='UTF-8')
    stdout, stderr = process.communicate()

    if process.returncode != 0:
        # /bin/copyright returns non-zero when it finds copyrights — that's expected
        logging.warning(f"{scanner_path} exited with code {process.returncode} (normal when findings exist)")
        if stderr:
            logging.warning(f"stderr: {stderr.strip()[:500]}")

    if not stdout.strip():
        return {}

    return json.loads(stdout.strip())


# ─────────────────────────────────────────────────────────────
# Collect findings from scanner JSON output
# ─────────────────────────────────────────────────────────────

def collect_findings(scanners: list[str], dir_to_scan: str) -> dict:
    findings: dict[str, dict] = {}

    def _ensure_entry(path):
        if path not in findings:
            findings[path] = {"copyrights": [], "licenses": []}

    if 'copyright' in scanners:
        logging.info("Scanning for copyrights...")
        raw = run_scanner(SCANNERS['copyright'], dir_to_scan)
        for entry in _get_results_list(raw):
            path = _normalize_path(entry.get('file', ''), dir_to_scan)
            if not path:
                continue
            _ensure_entry(path)

            for finding in (entry.get('results') or []):
                if finding is None:
                    continue
                if finding.get('type') == 'statement' and finding.get('content'):
                    text = finding['content'].strip()
                    if text and text not in findings[path]["copyrights"]:
                        findings[path]["copyrights"].append(text)

    if 'nomos' in scanners:
        logging.info("Scanning for licenses (nomos)...")
        nomos_extra = ["-S", "-l", "-n", str(max(1, multiprocessing.cpu_count() - 1))]
        raw = run_scanner(SCANNERS['nomos'], dir_to_scan, extra_args=nomos_extra)
        for entry in _get_results_list(raw):
            path = _normalize_path(entry.get('file', ''), dir_to_scan)
            if not path:
                continue
            _ensure_entry(path)

            for finding in (entry.get('results') or []):
                if finding is None:
                    continue
                lic = (finding.get('license') or '').strip()
                if lic and lic not in ('No_license_found', 'NOASSERTION', 'NONE', ''):
                    if lic not in findings[path]["licenses"]:
                        findings[path]["licenses"].append(lic)

    if 'ojo' in scanners:
        logging.info("Scanning for license references (ojo)...")
        raw = run_scanner(SCANNERS['ojo'], dir_to_scan)
        for entry in _get_results_list(raw):
            path = _normalize_path(entry.get('file', ''), dir_to_scan)
            if not path:
                continue
            _ensure_entry(path)

            for finding in (entry.get('results') or []):
                if finding is None:
                    continue
                lic = (finding.get('license') or '').strip()
                if lic and lic not in ('NOASSERTION', 'NONE', ''):
                    if lic not in findings[path]["licenses"]:
                        findings[path]["licenses"].append(lic)

    if 'keyword' in scanners:
        logging.info("Scanning for keywords...")
        raw = run_scanner(SCANNERS['keyword'], dir_to_scan)
        for entry in _get_results_list(raw):
            path = _normalize_path(entry.get('file', ''), dir_to_scan)
            if not path:
                continue
            _ensure_entry(path)
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
# TEXT report generator (matches fossology/fossology-action format)
# ─────────────────────────────────────────────────────────────

def write_text_report(findings: dict, output_dir: str,
                      scanners_used: list[str]) -> str:
    """Write a plain-text report matching the official FOSSology scanner output."""
    report_path = os.path.join(output_dir, 'scan_report.txt')

    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("=" * 70 + "\n")
        f.write("FOSSology Scanner Report\n")
        f.write(f"Scanners used: {', '.join(scanners_used)}\n")
        f.write("=" * 70 + "\n\n")

        if not findings:
            f.write("No findings.\n")
        else:
            for filepath in sorted(findings.keys()):
                data = findings[filepath]
                copyrights = data.get("copyrights", [])
                licenses = data.get("licenses", [])
                if not copyrights and not licenses:
                    continue

                f.write(f"File: {filepath}\n")
                for entry in copyrights:
                    if entry.startswith("[keyword]"):
                        f.write(f"  Keyword: {entry[len('[keyword] '):]}\n")
                    else:
                        f.write(f"  Copyright: {entry}\n")
                for lic in licenses:
                    f.write(f"  License: {lic}\n")
                f.write("\n")

        f.write("=" * 70 + "\n")
        total_cr = sum(
            1 for d in findings.values()
            for c in d.get("copyrights", [])
            if not c.startswith("[keyword]")
        )
        total_kw = sum(
            1 for d in findings.values()
            for c in d.get("copyrights", [])
            if c.startswith("[keyword]")
        )
        total_lic = sum(
            len(d.get("licenses", []))
            for d in findings.values()
        )
        f.write(f"Total files scanned: {len(findings)}\n")
        f.write(f"Total copyrights found: {total_cr}\n")
        f.write(f"Total licenses found: {total_lic}\n")
        f.write(f"Total keywords found: {total_kw}\n")
        f.write("=" * 70 + "\n")

    return report_path


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

    report_format = (args.report or 'TEXT').upper()

    logging.info(f"Scanners: {', '.join(scanners_to_run)}")
    logging.info(f"Report format: {report_format}")
    logging.info(f"Directory: {dir_to_scan}")

    findings = collect_findings(scanners_to_run, dir_to_scan)

    cr_count = sum(len(f["copyrights"]) for f in findings.values())
    lic_count = sum(len(f.get("licenses", [])) for f in findings.values())
    logging.info(f"Collected {cr_count} copyright(s), {lic_count} license(s) across {len(findings)} file(s)")

    output_path = args.output
    output_dir = os.path.dirname(os.path.abspath(output_path))
    os.makedirs(output_dir, exist_ok=True)

    # Write findings.json as a debug/audit artifact
    findings_path = os.path.join(output_dir, 'findings.json')
    with open(findings_path, 'w', encoding='utf-8') as f:
        json.dump(findings, f, indent=2, ensure_ascii=False)
    logging.info(f"Raw scan findings written to {findings_path}")

    # Generate TEXT report (matches fossology-action output)
    text_report = write_text_report(findings, output_dir, scanners_to_run)
    logging.info(f"TEXT report written to {text_report}")

    # Always generate SPDX 3.0 JSON-LD (our value-add)
    spdx3_builder.build(
        repo_root=dir_to_scan,
        report_dir=None,
        output_path=output_path,
        findings_override=findings,
    )

    logging.info(f"SPDX 3.0 JSON-LD written to {output_path}")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="FOSSology SPDX 3.0 Scanner (compatible with fossology/fossology-action)",
    )

    parser.add_argument(
        "scanners", type=str, nargs='*', default=['copyright'],
        help="Scanners to run: nomos, ojo, copyright, keyword (default: copyright)",
    )

    parser.add_argument(
        "--scan-dir", type=str, default=".",
        help="Directory to scan (default: current directory)",
    )

    parser.add_argument(
        "--report", type=str, default="TEXT",
        help="Report format: TEXT, SPDX_JSON (default: TEXT). SPDX 3.0 JSON-LD is always generated.",
    )

    parser.add_argument(
        "--output", type=str, default="results/spdx3_report.jsonld",
        help="Output path for SPDX 3.0 JSON-LD (default: results/spdx3_report.jsonld)",
    )

    parsed = parser.parse_args()
    sys.exit(main(parsed))
