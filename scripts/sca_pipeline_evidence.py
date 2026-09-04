#!/usr/bin/env python3
"""Run and verify the SCA workflow using only real GitHub Actions evidence.

This tool deliberately does not create SBOMs, SW360 objects, source archives,
reports, or fake GitHub Actions artifacts. It can dispatch the unchanged
workflow only when the requested scenario is declared by that workflow. For
the current production workflow, scenario-specific cases are reported as
NOT_APPLICABLE because the workflow has no scenario input or fixture hook.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Optional
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen


SCENARIOS = {
    "E01": "existing component and release are reused",
    "E02": "existing component is reused and missing release is created",
    "E03": "component and release are created",
    "E04": "inconsistent component/release state is handled diagnostically",
    "E05": "exact name/version mapping succeeds",
    "E06": "wrong version creates a new release",
    "E07": "wrong-name/case mapping is handled without a false match",
    "E08": "multiple release matches do not map randomly",
    "E10": "missing release ID is detected after mapping",
    "C01": "REPORT_AVAILABLE is skipped",
    "C02": "APPROVED is skipped and preserved",
    "C03": "NEW is included for scanning",
    "C07": "missing release ID is included as NO_SW360_ID",
    "C11": "mixed clearing states are filtered independently",
    "C12": "all cleared components produce an empty filtered SBOM",
    "C13": "no cleared components are filtered out",
    "S01": "valid source archive is scanned and staged",
    "S02": "missing source URL fails before upload",
    "S04": "404/403 source URL fails download",
    "S06": "source timeout retries and then fails",
    "S07": "VCS web page is rejected as a source archive",
    "S08": "valid raw source archive downloads",
    "S14": "wrong source content fails hash verification",
    "S19": "unsupported package type fails source coverage",
    "A01": "missing source attachment fails verification",
    "A02": "correct source filename and SHA-1 verify",
    "A03": "wrong source SHA-1 fails verification",
    "A08": "missing local source fails verification",
    "A09": "attachment upload failure blocks report upload",
    "A10": "attachment upload retry can recover",
    "U01": "report upload succeeds on first attempt",
    "U02": "report upload retry succeeds",
    "U03": "report upload fails after three attempts",
    "U09": "rerunning the same report does not duplicate it",
    "U11": "empty filtered SBOM skips report upload and state update",
    "F01": "final SBOM preserves all enriched components",
    "F02": "final SBOM loss of a skipped component is detected",
    "F03": "final SBOM loss of a scanned component is detected",
    "F04": "missing SW360 ID is detected",
    "F06": "missing project metadata is detected",
    "F08": "missing final SBOM is detected",
    "P01": "missing project is created and persisted",
    "P02": "existing project is reused or updated",
    "P07": "mapping has no missing entities",
    "P11": "missing or invalid SW360 token fails API operations",
    "P13": "SW360 unavailability produces a useful failure",
}


class EvidenceError(RuntimeError):
    pass


class SafeRedirectHandler(HTTPRedirectHandler):
    """Prevent GitHub credentials being forwarded to artifact storage."""

    def redirect_request(self, request: Request, response: Any, code: int,
                         message: str, headers: Any, new_url: str) -> Optional[Request]:
        redirected = super().redirect_request(request, response, code, message, headers, new_url)
        if redirected and urlparse(request.full_url).netloc != urlparse(new_url).netloc:
            redirected.remove_header("Authorization")
        return redirected


class GitHub:
    def __init__(self, repository: str, token: str) -> None:
        self.repository = repository
        self.base = "https://api.github.com"
        self.opener = build_opener(SafeRedirectHandler)
        self.headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "sca-pipeline-evidence",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def request(self, method: str, path: str, payload: Any = None,
                accept: Optional[str] = None) -> tuple[int, bytes]:
        headers = dict(self.headers)
        if accept:
            headers["Accept"] = accept
        body = None
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(self.base + "/" + path.lstrip("/"), data=body,
                          headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=60) as response:
                return response.status, response.read()
        except HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")[:1000]
            raise EvidenceError(f"GitHub API HTTP {error.code} for {method} {path}: {detail}") from error
        except URLError as error:
            raise EvidenceError(f"GitHub API request failed for {method} {path}: {error.reason}") from error

    def json(self, method: str, path: str, payload: Any = None) -> Any:
        status, content = self.request(method, path, payload)
        if not 200 <= status < 300:
            raise EvidenceError(f"GitHub API returned HTTP {status} for {method} {path}")
        try:
            return json.loads(content.decode("utf-8")) if content else {}
        except json.JSONDecodeError as error:
            raise EvidenceError(f"GitHub returned invalid JSON for {method} {path}") from error

    def bytes(self, path: str) -> bytes:
        _, content = self.request("GET", path, accept="application/vnd.github+json")
        return content


def repository_from_git() -> Optional[str]:
    import subprocess

    try:
        remote = subprocess.check_output(
            ["git", "config", "--get", "remote.origin.url"],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    if remote.startswith("https://github.com/"):
        return remote.removeprefix("https://github.com/").removesuffix(".git")
    if remote.startswith("git@github.com:"):
        return remote.removeprefix("git@github.com:").removesuffix(".git")
    return None


def workflow_text(api: GitHub, workflow: str, ref: str) -> str:
    path = f"repos/{api.repository}/contents/{quote(workflow, safe='/')}?{urlencode({'ref': ref})}"
    data = api.json("GET", path)
    if data.get("encoding") != "base64" or not data.get("content"):
        raise EvidenceError(f"Workflow source {workflow}@{ref} was not returned as base64 content")
    return base64.b64decode(data["content"]).decode("utf-8")


def workflow_api_id(workflow: str) -> str:
    """Return the filename/ID form accepted by Actions workflow endpoints."""
    return Path(workflow).name


def workflow_supports_scenarios(text: str) -> tuple[bool, bool]:
    has_input = bool(re.search(r"(?m)^\s{4,}scenario:\s*$", text))
    has_job = bool(re.search(r"(?m)^\s{2}clearing-state-scenario:\s*$", text))
    return has_input, has_job


def ensure_token(args: argparse.Namespace) -> str:
    token = args.github_token or os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if not token:
        raise EvidenceError("Set GITHUB_TOKEN or GH_TOKEN; do not put a token in a file")
    return token


def safe_extract(content: bytes, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    archive_path = destination / ".download.zip"
    archive_path.write_bytes(content)
    try:
        with zipfile.ZipFile(archive_path) as archive:
            for member in archive.infolist():
                parts = PurePosixPath(member.filename).parts
                if PurePosixPath(member.filename).is_absolute() or ".." in parts:
                    raise EvidenceError(f"Unsafe path in GitHub ZIP: {member.filename}")
                archive.extract(member, destination)
    except zipfile.BadZipFile as error:
        raise EvidenceError(f"GitHub returned a non-ZIP archive for {destination}") from error
    finally:
        archive_path.unlink(missing_ok=True)


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def collect_run(api: GitHub, run_id: int, destination: Path) -> Path:
    run = api.json("GET", f"repos/{api.repository}/actions/runs/{run_id}")
    jobs = api.json("GET", f"repos/{api.repository}/actions/runs/{run_id}/jobs?per_page=100")
    artifacts = api.json("GET", f"repos/{api.repository}/actions/runs/{run_id}/artifacts?per_page=100")
    destination.mkdir(parents=True, exist_ok=True)
    write_json(destination / "run.json", run)
    write_json(destination / "jobs.json", jobs)
    write_json(destination / "artifacts.json", artifacts)
    safe_extract(api.bytes(f"repos/{api.repository}/actions/runs/{run_id}/logs"), destination / "logs")
    for artifact in artifacts.get("artifacts", []):
        if artifact.get("expired"):
            continue
        name = str(artifact.get("name", "artifact"))
        artifact_id = artifact.get("id")
        if not artifact_id:
            raise EvidenceError(f"Artifact {name} has no GitHub artifact ID")
        safe_extract(
            api.bytes(f"repos/{api.repository}/actions/artifacts/{artifact_id}/zip"),
            destination / "artifacts" / name,
        )
    return destination


def wait_for_run(api: GitHub, workflow: str, ref: str, before_ids: set[int],
                 dispatch_time: str, timeout_minutes: int, poll_seconds: int) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_minutes * 60
    encoded_workflow = quote(workflow_api_id(workflow), safe="/")
    query = urlencode({"event": "workflow_dispatch", "branch": ref, "per_page": 100})
    run: Optional[dict[str, Any]] = None
    while time.monotonic() < deadline:
        data = api.json("GET", f"repos/{api.repository}/actions/workflows/{encoded_workflow}/runs?{query}")
        candidates = [
            item for item in data.get("workflow_runs", [])
            if int(item.get("id", 0)) not in before_ids
            and str(item.get("created_at", "")) >= dispatch_time
        ]
        if candidates:
            run = max(candidates, key=lambda item: int(item["id"]))
            break
        time.sleep(poll_seconds)
    if not run:
        raise EvidenceError("No workflow run appeared after dispatch before the timeout")

    run_id = int(run["id"])
    while time.monotonic() < deadline:
        run = api.json("GET", f"repos/{api.repository}/actions/runs/{run_id}")
        print(f"SCA_RUN_STATUS run_id={run_id} status={run.get('status')} conclusion={run.get('conclusion') or 'pending'}", flush=True)
        if run.get("status") == "completed":
            return run
        time.sleep(poll_seconds)
    raise EvidenceError(f"Workflow run {run_id} did not complete before the timeout")


def find_one(root: Path, filename: str) -> Optional[Path]:
    matches = [path for path in root.rglob(filename) if path.is_file()]
    return matches[0] if len(matches) == 1 else None


def read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError(f"Cannot read JSON evidence {path}: {error}") from error


def components(document: Any, label: str) -> list[dict[str, Any]]:
    if not isinstance(document, dict) or not isinstance(document.get("components"), list):
        raise EvidenceError(f"{label} is not a JSON SBOM with a components list")
    if any(not isinstance(item, dict) for item in document["components"]):
        raise EvidenceError(f"{label} contains a non-object component")
    return document["components"]


def prop(component: dict[str, Any], name: str) -> Optional[str]:
    for item in component.get("properties", []):
        if item.get("name") == name and item.get("value") not in (None, ""):
            return str(item["value"])
    return None


def verify_run(evidence_dir: Path) -> dict[str, Any]:
    run = read_json(evidence_dir / "run.json")
    jobs = read_json(evidence_dir / "jobs.json").get("jobs", [])
    artifacts = read_json(evidence_dir / "artifacts.json").get("artifacts", [])
    artifact_names = {str(item.get("name")) for item in artifacts if not item.get("expired")}
    checks: list[dict[str, str]] = []

    def add(name: str, status: str, message: str) -> None:
        checks.append({"check": name, "status": status, "message": message})
        print(f"SCA_CHECK check={name} status={status} message={message}", flush=True)

    if run.get("conclusion") == "success":
        add("workflow_conclusion", "PASS", "GitHub Actions concluded success")
    else:
        add("workflow_conclusion", "FAIL", f"GitHub Actions conclusion={run.get('conclusion')}")

    required_jobs = {
        "Generate SBOM", "Map & create in SW360", "Create SW360 project",
        "Filter by clearing state", "Download & FOSSology scan",
        "Upload to SW360", "Validate pipeline",
    }
    job_by_name = {str(item.get("name")): item for item in jobs}
    for name in sorted(required_jobs):
        job = job_by_name.get(name)
        if not job:
            add(f"job:{name}", "FAIL", "required job is absent from the real run")
        elif job.get("conclusion") == "success":
            add(f"job:{name}", "PASS", "job concluded success")
        else:
            add(f"job:{name}", "FAIL", f"job conclusion={job.get('conclusion')}")

    roots = {name: evidence_dir / "artifacts" / name for name in artifact_names}
    for name in ("sbom", "created-sbom", "enriched-sbom", "filtered-sbom", "scan-artifacts", "final-sbom"):
        add(f"artifact:{name}", "PASS" if name in roots else "FAIL",
            "artifact was downloaded from GitHub" if name in roots else "artifact is missing from the real run")

    sbom_paths = {
        "sbom": find_one(roots.get("sbom", Path()), "sbom.json"),
        "created": find_one(roots.get("created-sbom", Path()), "created-sbom.json"),
        "enriched": find_one(roots.get("enriched-sbom", Path()), "enriched-sbom.json"),
        "filtered": find_one(roots.get("filtered-sbom", Path()), "filtered-sbom.json"),
        "final": find_one(roots.get("final-sbom", Path()), "final-sbom.json"),
    }
    documents: dict[str, Any] = {}
    for name, path in sbom_paths.items():
        if path:
            try:
                documents[name] = read_json(path)
                components(documents[name], name)
                add(f"json:{name}", "PASS", "downloaded file is a CycloneDX document with components")
            except EvidenceError as error:
                add(f"json:{name}", "FAIL", str(error))
        else:
            add(f"json:{name}", "FAIL", "expected SBOM file is absent from downloaded artifact")

    refs: dict[str, set[str]] = {}
    for name, document in documents.items():
        values = [str(item.get("bom-ref", "")) for item in components(document, name)]
        refs[name] = set(values)
        if len(values) != len(refs[name]) or "" in refs[name]:
            add(f"refs:{name}", "FAIL", "component bom-ref values are missing or duplicated")
        else:
            add(f"refs:{name}", "PASS", f"{len(values)} unique component bom-ref values")

    if "created" in refs and "enriched" in refs:
        add("filter_input_preserved", "PASS" if refs["created"] == refs["enriched"] else "FAIL",
            "enriched SBOM preserves created SBOM membership" if refs["created"] == refs["enriched"] else "enriched SBOM changed component membership")
    if "enriched" in refs and "filtered" in refs:
        add("filtered_is_subset", "PASS" if refs["filtered"] <= refs["enriched"] else "FAIL",
            f"filtered={len(refs['filtered'])}, enriched={len(refs['enriched'])}")
    if "enriched" in refs and "final" in refs:
        add("final_preserves_enriched", "PASS" if refs["final"] == refs["enriched"] else "FAIL",
            "final SBOM preserves every enriched component" if refs["final"] == refs["enriched"] else "final SBOM component membership differs from enriched SBOM")

    if "created" in documents:
        created_items = components(documents["created"], "created")
        missing_ids = [str(item.get("name", "<unnamed>")) for item in created_items if not prop(item, "siemens:sw360Id")]
        add("created_release_ids", "PASS" if not missing_ids else "FAIL",
            "every created component has a SW360 release ID" if not missing_ids else f"missing SW360 IDs: {', '.join(missing_ids[:5])}")
    if "enriched" in documents:
        enriched_items = components(documents["enriched"], "enriched")
        missing_states = [str(item.get("name", "<unnamed>")) for item in enriched_items if not prop(item, "siemens:clearingState")]
        add("clearing_state_enrichment", "PASS" if not missing_states else "FAIL",
            "every enriched component has a clearing state" if not missing_states else f"missing clearing states: {', '.join(missing_states[:5])}")
    if "final" in documents:
        final_items = components(documents["final"], "final")
        missing_final = [str(item.get("name", "<unnamed>")) for item in final_items if not prop(item, "siemens:sw360Id") or not prop(item, "siemens:sw360ReleaseUrl")]
        add("final_release_metadata", "PASS" if not missing_final else "FAIL",
            "every final component has SW360 ID and release URL" if not missing_final else f"missing final release metadata: {', '.join(missing_final[:5])}")
        metadata = documents["final"].get("metadata", {}).get("properties", [])
        required_meta = {"siemens:sw360ProjectId", "siemens:sw360ProjectName", "siemens:sw360ProjectVersion", "siemens:sw360ProjectUrl"}
        actual_meta = {str(item.get("name")) for item in metadata if item.get("name") in required_meta and item.get("value") not in (None, "")}
        add("final_project_metadata", "PASS" if actual_meta == required_meta else "FAIL",
            "final SBOM contains complete project metadata" if actual_meta == required_meta else f"missing project metadata: {', '.join(sorted(required_meta - actual_meta))}")

    scan_root = roots.get("scan-artifacts", Path())
    manifest_path = find_one(scan_root, "source-manifest.json")
    filtered_count = len(refs.get("filtered", set()))
    if manifest_path:
        manifest = read_json(manifest_path)
        if not isinstance(manifest, list):
            add("source_manifest", "FAIL", "source-manifest.json is not a list")
        elif len(manifest) != filtered_count:
            add("source_manifest", "FAIL", f"manifest covers {len(manifest)} of {filtered_count} filtered components")
        else:
            bad_entries = [item for item in manifest if not all(item.get(key) for key in ("bom_ref", "release_id", "source_filename"))]
            add("source_manifest", "PASS" if not bad_entries else "FAIL",
                "source manifest covers every filtered component" if not bad_entries else "source manifest contains incomplete entries")
    else:
        add("source_manifest", "FAIL", "source-manifest.json is absent from scan-artifacts")

    if filtered_count == 0:
        add("empty_scan_gate", "PASS", "filtered SBOM is empty; scan/report upload is correctly unnecessary")
    else:
        report = find_one(scan_root, "sbom_spdx.json")
        reports = list(scan_root.rglob("*.spdx.json")) if scan_root.exists() else []
        add("fossology_report", "PASS" if report else "FAIL", "consolidated SPDX report downloaded" if report else "consolidated SPDX report is missing")
        add("per_dependency_reports", "PASS" if reports else "FAIL", f"{len(reports)} SPDX report(s) downloaded" if reports else "no per-dependency SPDX report was downloaded")

    log_text = "\n".join(path.read_text(encoding="utf-8", errors="replace") for path in (evidence_dir / "logs").rglob("*") if path.is_file())
    add("capycli_execution_evidence", "PASS" if "capycli" in log_text.lower() else "INCONCLUSIVE",
        "real job logs contain CapyCLI execution evidence" if "capycli" in log_text.lower() else "CapyCLI invocation was not identifiable in downloaded logs")
    add("fossology_action_evidence", "PASS" if "fossology" in log_text.lower() else "INCONCLUSIVE",
        "real job logs contain FOSSology execution evidence" if "fossology" in log_text.lower() else "FOSSology invocation was not identifiable in downloaded logs")

    failures = [item for item in checks if item["status"] == "FAIL"]
    inconclusive = [item for item in checks if item["status"] == "INCONCLUSIVE"]
    verdict = "FAIL" if failures else ("INCONCLUSIVE" if inconclusive else "PASS")
    result = {
        "verdict": verdict,
        "run_id": run.get("id"),
        "workflow_conclusion": run.get("conclusion"),
        "evidence_basis": "GitHub Actions run metadata, downloaded logs, and downloaded artifacts",
        "checks": checks,
        "failure_count": len(failures),
        "inconclusive_count": len(inconclusive),
    }
    write_json(evidence_dir / "verification.json", result)
    print(f"SCA_RESULT run_id={run.get('id')} verdict={verdict} failures={len(failures)} inconclusive={len(inconclusive)} evidence={evidence_dir}", flush=True)
    return result


def scenario_command(args: argparse.Namespace) -> int:
    scenario = args.scenario.upper()
    if scenario not in SCENARIOS:
        raise EvidenceError(f"Unknown scenario {scenario}; use catalog to list supported IDs")
    api = GitHub(args.repository or repository_from_git() or "", ensure_token(args))
    text = workflow_text(api, args.workflow, args.ref)
    has_input, has_job = workflow_supports_scenarios(text)
    if not (has_input and has_job):
        print(
            f"SCA_RESULT scenario={scenario} verdict=NOT_APPLICABLE "
            f"reason=workflow {args.workflow}@{args.ref} declares no scenario input/job; "
            "dispatching it would not test the requested case",
            flush=True,
        )
        return 2
    raise EvidenceError("Scenario dispatch support exists, but this repository workflow must define its own real fixture setup")


def production_command(args: argparse.Namespace) -> int:
    api = GitHub(args.repository or repository_from_git() or "", ensure_token(args))
    text = workflow_text(api, args.workflow, args.ref)
    has_dispatch = bool(re.search(r"(?m)^\s{2}workflow_dispatch:\s*$", text))
    if not has_dispatch:
        raise EvidenceError(f"Workflow {args.workflow}@{args.ref} has no workflow_dispatch trigger")
    workflow_id = workflow_api_id(args.workflow)
    runs = api.json("GET", f"repos/{api.repository}/actions/workflows/{quote(workflow_id, safe='/')}/runs?{urlencode({'branch': args.ref, 'per_page': 100})}")
    before_ids = {int(item["id"]) for item in runs.get("workflow_runs", []) if item.get("id")}
    dispatch_time = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    status, _ = api.request(
        "POST",
        f"repos/{api.repository}/actions/workflows/{quote(workflow_api_id(args.workflow), safe='/')}/dispatches",
        {"ref": args.ref},
    )
    if status != 204:
        raise EvidenceError(f"Workflow dispatch returned HTTP {status}")
    run = wait_for_run(api, args.workflow, args.ref, before_ids, dispatch_time, args.timeout_minutes, args.poll_seconds)
    run_id = int(run["id"])
    evidence = Path(args.evidence_dir) / str(run_id)
    collect_run(api, run_id, evidence)
    result = verify_run(evidence)
    return 0 if result["verdict"] == "PASS" else 1


def collect_command(args: argparse.Namespace) -> int:
    api = GitHub(args.repository or repository_from_git() or "", ensure_token(args))
    evidence = collect_run(api, args.run_id, Path(args.evidence_dir) / str(args.run_id))
    print(f"SCA_COLLECTED run_id={args.run_id} evidence={evidence}", flush=True)
    return 0


def verify_command(args: argparse.Namespace) -> int:
    result = verify_run(Path(args.evidence_dir) / str(args.run_id))
    return 0 if result["verdict"] == "PASS" else 1


def catalog_command(_: argparse.Namespace) -> int:
    print("ID\tDescription\tCurrent workflow status")
    for scenario, description in SCENARIOS.items():
        print(f"{scenario}\t{description}\tNOT_APPLICABLE without a declared fixture/input hook")
    print("PRODUCTION\tRun the unchanged workflow and verify its actual artifacts\tSUPPORTED")
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(description=__doc__)
    sub = root.add_subparsers(dest="command", required=True)

    catalog = sub.add_parser("catalog")
    catalog.set_defaults(function=catalog_command)

    scenario = sub.add_parser("scenario")
    scenario.add_argument("--scenario", required=True)
    scenario.add_argument("--repository")
    scenario.add_argument("--workflow", default=".github/workflows/sca-full-pipeline.yml")
    scenario.add_argument("--ref", default="main")
    scenario.add_argument("--github-token")
    scenario.set_defaults(function=scenario_command)

    production = sub.add_parser("run-production")
    production.add_argument("--repository")
    production.add_argument("--workflow", default=".github/workflows/sca-full-pipeline.yml")
    production.add_argument("--ref", default="main")
    production.add_argument("--github-token")
    production.add_argument("--evidence-dir", default=".sca-evidence")
    production.add_argument("--poll-seconds", type=int, default=15)
    production.add_argument("--timeout-minutes", type=int, default=120)
    production.set_defaults(function=production_command)

    collect = sub.add_parser("collect")
    collect.add_argument("--run-id", type=int, required=True)
    collect.add_argument("--repository")
    collect.add_argument("--github-token")
    collect.add_argument("--evidence-dir", default=".sca-evidence")
    collect.set_defaults(function=collect_command)

    verify = sub.add_parser("verify")
    verify.add_argument("--run-id", type=int, required=True)
    verify.add_argument("--evidence-dir", default=".sca-evidence")
    verify.set_defaults(function=verify_command)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        return int(args.function(args))
    except EvidenceError as error:
        print(f"SCA_RESULT verdict=INCONCLUSIVE reason={error}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())