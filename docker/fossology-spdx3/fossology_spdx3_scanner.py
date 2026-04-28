#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2026 Contributors
# SPDX-License-Identifier: MIT

"""
Modified FOSSology scanner that produces SPDX 3.0 JSON-LD directly.

Replaces the default fossologyscanner.py in the fossology/fossology:scanner
image. The C scanner binaries (nomossa, copyright, ojo, keyword) are the same
ones from the base image — only the *reporting pipeline* is replaced:

    scanner C binaries  →  Python scanner objects  →  SPDX 3.0 JSON-LD

No SPDX 2.x document is produced at any stage. No intermediate text or
SPDX 2.x files are written.

How it works:
  1. FoScanner.Scanners runs the C binaries and populates result objects
  2. collect_findings() reads ScanResult objects from the Scanners API:
       - scanner.get_copyright_results()  → per-file copyright findings
       - scanner.results_are_allow_listed()  → per-file license findings
  3. Findings are passed directly (in-memory) to spdx3_builder.build()
  4. The builder produces SPDX 3.0 JSON-LD from those findings + filesystem walk
"""

import argparse
import logging
import os
import sys

# FoScanner modules are installed at /bin/ in the scanner image
sys.path.insert(0, '/bin')

from FoScanner.ApiConfig import ApiConfig, Runner
from FoScanner.CliOptions import CliOptions
from FoScanner.Scanners import Scanners
from FoScanner.Packages import Packages

# SPDX 3.0 builder
sys.path.insert(0, '/opt')
import spdx3_builder

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')


# ─────────────────────────────────────────────────────────────
# CI Environment Setup
# ─────────────────────────────────────────────────────────────

def get_api_config() -> ApiConfig:
    """Configure API settings based on the CI environment."""
    api_config = ApiConfig()

    if os.environ.get('GITHUB_ACTIONS') == 'true':
        api_config.running_on = Runner.GITHUB
        api_config.api_url = os.environ.get('GITHUB_API', 'https://api.github.com')
        api_config.api_token = os.environ.get('GITHUB_TOKEN', '')
        api_config.github_repo_slug = os.environ.get('GITHUB_REPOSITORY', '')
        api_config.github_pull_request = os.environ.get('GITHUB_PULL_REQUEST', '')
        if api_config.github_repo_slug:
            api_config.project_name = api_config.github_repo_slug.split("/")[-1]
            api_config.project_orig = os.environ.get('GITHUB_REPO_OWNER', '')
            api_config.project_url = os.environ.get('GITHUB_REPO_URL', '')
    elif 'GITLAB_CI' in os.environ:
        api_config.running_on = Runner.GITLAB
        api_config.api_url = os.environ.get('CI_API_V4_URL', '')
        api_config.project_id = os.environ.get('CI_PROJECT_ID', '')
        api_config.mr_iid = os.environ.get('CI_MERGE_REQUEST_IID', '')
        api_config.api_token = os.environ.get('API_TOKEN', '')
        api_config.project_name = os.environ.get('CI_PROJECT_NAME', '')
        api_config.project_orig = os.environ.get('CI_PROJECT_NAMESPACE', '')
        api_config.project_url = os.environ.get('CI_PROJECT_URL', '')

    return api_config


# ─────────────────────────────────────────────────────────────
# Scanner Result Collection
# ─────────────────────────────────────────────────────────────

def collect_findings(scanner: Scanners, cli_options: CliOptions) -> dict:
    """Run scanners and collect per-file findings directly from scanner objects.

    Reads results from the Scanners API (no file I/O, no intermediate formats).

    Returns:
        {filepath: {"licenses": [...], "copyrights": [...], "checksums": {}}}
    """
    findings: dict[str, dict] = {}

    # ── Copyright scanner ──
    if cli_options.copyright:
        logging.info("Scanning for copyrights...")
        scanner.set_copyright_list(all_results=True, whole=True)
        for scan_result in scanner.get_copyright_results():
            path = scan_result.file
            if path not in findings:
                findings[path] = {"licenses": [], "copyrights": [], "checksums": {}}

            if scan_result.result:
                items = scan_result.result if isinstance(scan_result.result, list) else [scan_result.result]
                for item in items:
                    if isinstance(item, dict):
                        text = item.get('content', '')
                    else:
                        text = str(item)
                    if text and text not in findings[path]["copyrights"]:
                        findings[path]["copyrights"].append(text)

    # ── License scanners (nomos / ojo) ──
    if cli_options.nomos or cli_options.ojo:
        logging.info("Scanning for licenses...")
        scanner.set_scanner_results(whole=True)
        # Without an allowlist loaded, all detected licenses are returned
        # as "not allowed" — which is what we want for SBOM (capture everything).
        license_results = scanner.results_are_allow_listed()
        if isinstance(license_results, list):
            for scan_result in license_results:
                path = scan_result.file
                if path not in findings:
                    findings[path] = {"licenses": [], "copyrights": [], "checksums": {}}

                if scan_result.result:
                    items = scan_result.result if isinstance(scan_result.result, list) else [scan_result.result]
                    for item in items:
                        if isinstance(item, dict):
                            lic = item.get('license', '')
                        else:
                            lic = str(item)
                        if lic and lic not in findings[path]["licenses"]:
                            findings[path]["licenses"].append(lic)

    # ── Normalize file paths ──
    # Scanner reports paths relative to /opt/repo or with ./ prefix; strip those.
    normalized: dict[str, dict] = {}
    for path, data in findings.items():
        clean = path
        for prefix in ('/opt/repo/', './'):
            if clean.startswith(prefix):
                clean = clean[len(prefix):]
        normalized[clean] = data

    return normalized


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

def main(args: argparse.Namespace) -> int:
    api_config = get_api_config()

    # Set up CliOptions the same way the original scanner does.
    # update_args reads args.operation to set cli_options.nomos, .copyright,
    # .repo, etc., and args.report to set cli_options.report_format.
    cli_options = CliOptions()
    cli_options.update_args(args)

    # Do NOT load an allowlist — we want ALL detected licenses in the SBOM,
    # not just "violations". Without an allowlist, results_are_allow_listed()
    # returns every detected license.

    scan_packages = Packages()
    scan_packages.parent_package = {
        'name': getattr(api_config, 'project_name', '') or os.path.basename(os.getcwd()),
        'description': getattr(api_config, 'project_desc', None),
        'author': getattr(api_config, 'project_orig', ''),
        'url': getattr(api_config, 'project_url', ''),
    }

    # For repo mode, scan the mounted repository
    if cli_options.repo:
        cli_options.diff_dir = '/opt/repo'

    logging.info("Initializing scanners...")
    scanner = Scanners(cli_options, scan_packages)

    # ── Collect findings directly from scanner objects (no files written) ──
    findings = collect_findings(scanner, cli_options)

    copyright_count = sum(len(f["copyrights"]) for f in findings.values())
    license_count = sum(len(f["licenses"]) for f in findings.values())
    logging.info(
        f"Collected {copyright_count} copyright(s) and {license_count} license(s) "
        f"across {len(findings)} file(s)"
    )

    # ── Build SPDX 3.0 JSON-LD directly from in-memory findings ──
    output_path = args.output
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)

    spdx3_builder.build(
        repo_root='/opt/repo',
        report_dir=None,
        output_path=output_path,
        findings_override=findings,
    )

    logging.info(f"SPDX 3.0 JSON-LD written to {output_path}")
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="FOSSology SPDX 3.0 Scanner — produces SPDX 3.0 JSON-LD directly.",
    )

    # Scanner/mode selection (same positional format as the original scanner
    # so that CliOptions.update_args can parse it unchanged)
    parser.add_argument(
        "operation", type=str, nargs='*',
        choices=["nomos", "copyright", "keyword", "ojo",
                 "repo", "differential", "scan-only-deps", "scan-dir"],
        help="Scanners to run and scan mode (e.g. 'copyright repo')",
    )

    # Arguments required by CliOptions.update_args (kept for compatibility
    # with the FoScanner internals, but not used for reporting)
    parser.add_argument("--report", type=str, default="TEXT",
                        help=argparse.SUPPRESS)
    parser.add_argument("--tags", type=str, nargs=2, default=None,
                        help=argparse.SUPPRESS)
    parser.add_argument("--keyword-conf", type=str, default=None,
                        help=argparse.SUPPRESS)
    parser.add_argument("--dir-path", type=str, default=None,
                        help=argparse.SUPPRESS)
    parser.add_argument("--allowlist-path", type=str, default=None,
                        help=argparse.SUPPRESS)
    parser.add_argument("--sbom-path", type=str, default=None,
                        help=argparse.SUPPRESS)

    # Our SPDX 3.0-specific arguments
    parser.add_argument(
        "--output", type=str, default="results/sbom_spdx3.jsonld",
        help="Output path for SPDX 3.0 JSON-LD (default: results/sbom_spdx3.jsonld)",
    )

    parsed = parser.parse_args()
    sys.exit(main(parsed))
