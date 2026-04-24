#!/usr/bin/env python3
"""Tests for spdx3_builder.py — covers all known bugs and critical functionality.

Run: python -m pytest scripts/test_spdx3_builder.py -v
  or: python scripts/test_spdx3_builder.py
"""

import hashlib
import json
import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest.mock import patch

# Ensure the scripts directory is importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import spdx3_builder as sb


# ═════════════════════════════════════════════════════════════════════
# Bug #1: File ID collision — files with identical content (same SHA-256)
#          must get unique @ids (sequential index, not hash prefix)
# ═════════════════════════════════════════════════════════════════════

class TestFileIDUniqueness(unittest.TestCase):
    """Files with identical SHA-256 must produce unique element IDs."""

    def test_identical_files_get_unique_ids(self):
        """200 empty files (same SHA-256) must all have distinct @id values."""
        same_hash = hashlib.sha256(b"").hexdigest()
        files = [
            {"path": f"dir/empty_{i}.txt", "sha256": same_hash,
             "mime_type": "text/plain", "purpose": "source",
             "licenses": [], "copyrights": []}
            for i in range(200)
        ]

        file_elements, _ = sb.build_file_elements(files, "urn:spdx:test/abc123", [0])

        ids = [e["@id"] for e in file_elements]
        self.assertEqual(len(ids), len(set(ids)),
                         f"Duplicate file IDs found: {len(ids) - len(set(ids))} collisions")

    def test_file_ids_are_sequential(self):
        """File IDs must use sequential indices, not hash prefixes."""
        files = [
            {"path": f"file_{i}.txt", "sha256": f"{'a' * 64}",
             "mime_type": "text/plain", "purpose": "source",
             "licenses": [], "copyrights": []}
            for i in range(5)
        ]
        base = "urn:spdx:test/abc123"
        file_elements, _ = sb.build_file_elements(files, base, [0])

        for idx, elem in enumerate(file_elements):
            self.assertEqual(elem["@id"], f"{base}/File/{idx}")

    def test_file_sha256_still_recorded(self):
        """SHA-256 hash must still be in verifiedUsing despite not being in @id."""
        sha = hashlib.sha256(b"hello world").hexdigest()
        files = [
            {"path": "test.txt", "sha256": sha,
             "mime_type": "text/plain", "purpose": "source",
             "licenses": [], "copyrights": []}
        ]
        file_elements, _ = sb.build_file_elements(files, "urn:spdx:test/abc", [0])

        self.assertIn("verifiedUsing", file_elements[0])
        self.assertEqual(file_elements[0]["verifiedUsing"][0]["hashValue"], sha)


# ═════════════════════════════════════════════════════════════════════
# Bug #2: npm license dict format — license field can be a dict or list
# ═════════════════════════════════════════════════════════════════════

class TestNpmLicenseDictFormat(unittest.TestCase):
    """npm package-lock.json license field can be dict, string, or other types."""

    def _make_lockfile(self, packages_data: dict) -> str:
        """Write a temporary package-lock.json and return its path."""
        lock = {"lockfileVersion": 3, "packages": packages_data}
        tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        )
        json.dump(lock, tmp)
        tmp.close()
        return tmp.name

    def tearDown(self):
        # Clean up any temp files
        for attr in ("_tmpfile",):
            path = getattr(self, attr, None)
            if path and os.path.exists(path):
                os.unlink(path)

    def test_license_as_string(self):
        """Standard string license should be extracted correctly."""
        self._tmpfile = self._make_lockfile({
            "node_modules/foo": {"version": "1.0.0", "license": "MIT"}
        })
        pkgs = sb.parse_npm_lockfile(self._tmpfile)
        self.assertEqual(len(pkgs), 1)
        self.assertEqual(pkgs[0]["license"], "MIT")

    def test_license_as_dict(self):
        """Dict license {\"type\": \"MIT\"} should extract the type field."""
        self._tmpfile = self._make_lockfile({
            "node_modules/bar": {"version": "2.0.0", "license": {"type": "ISC", "url": "..."}}
        })
        pkgs = sb.parse_npm_lockfile(self._tmpfile)
        self.assertEqual(len(pkgs), 1)
        self.assertEqual(pkgs[0]["license"], "ISC")

    def test_license_as_list(self):
        """Non-string/non-dict license should default to empty string."""
        self._tmpfile = self._make_lockfile({
            "node_modules/baz": {"version": "3.0.0", "license": ["MIT", "Apache-2.0"]}
        })
        pkgs = sb.parse_npm_lockfile(self._tmpfile)
        self.assertEqual(len(pkgs), 1)
        self.assertEqual(pkgs[0]["license"], "")

    def test_license_missing(self):
        """Missing license field should default to empty string."""
        self._tmpfile = self._make_lockfile({
            "node_modules/qux": {"version": "4.0.0"}
        })
        pkgs = sb.parse_npm_lockfile(self._tmpfile)
        self.assertEqual(len(pkgs), 1)
        self.assertEqual(pkgs[0]["license"], "")


# ═════════════════════════════════════════════════════════════════════
# Bug #3: Package ID includes version — prevents collisions between
#          same-name packages with different versions
# ═════════════════════════════════════════════════════════════════════

class TestPackageIDIncludesVersion(unittest.TestCase):
    """Package @id must include version to avoid collisions."""

    def test_same_name_different_version_unique_ids(self):
        """Two packages with same name but different versions → distinct IDs."""
        packages = [
            {"name": "lodash", "version": "4.17.21", "ecosystem": "npm",
             "purl": "pkg:npm/lodash@4.17.21", "license": "MIT"},
            {"name": "lodash", "version": "3.10.1", "ecosystem": "npm",
             "purl": "pkg:npm/lodash@3.10.1", "license": "MIT"},
        ]
        pkg_elements, _ = sb.build_package_elements(packages, "urn:spdx:test/abc", [0])

        ids = [e["@id"] for e in pkg_elements]
        self.assertEqual(len(ids), 2, "Dedup should not collapse different versions")
        self.assertNotEqual(ids[0], ids[1], "Same-name packages must have different IDs due to version")

    def test_version_in_package_id(self):
        """Package ID must contain the version slug."""
        packages = [
            {"name": "react", "version": "18.2.0", "ecosystem": "npm",
             "purl": "pkg:npm/react@18.2.0", "license": "MIT"},
        ]
        pkg_elements, _ = sb.build_package_elements(packages, "urn:spdx:test/abc", [0])

        self.assertIn("18.2.0", pkg_elements[0]["@id"])

    def test_no_version_fallback(self):
        """Package without version should still get a valid ID."""
        packages = [
            {"name": "unknown-pkg", "version": "", "ecosystem": "maven",
             "purl": "", "license": ""},
        ]
        pkg_elements, _ = sb.build_package_elements(packages, "urn:spdx:test/abc", [0])

        self.assertEqual(len(pkg_elements), 1)
        self.assertIn("unknown-pkg", pkg_elements[0]["@id"])
        self.assertFalse(pkg_elements[0]["@id"].endswith("-"))


# ═════════════════════════════════════════════════════════════════════
# Bug #4: walk_filesystem must NOT use clearing policy excludes
# ═════════════════════════════════════════════════════════════════════

class TestWalkDoesNotUseClearingExcludes(unittest.TestCase):
    """Filesystem walk must only use DEFAULT_EXCLUDES, not clearing policy."""

    def test_clearing_exclude_files_still_appear(self):
        """Files matching clearing policy excludes must still be walked."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create files that match clearing-policy exclude patterns
            img = Path(tmpdir) / "logo.png"
            img.write_bytes(b"\x89PNG")
            js = Path(tmpdir) / "app.js"
            js.write_text("console.log('hello');", encoding="utf-8")

            # Walk with NO extra excludes (as the builder does)
            files = sb.walk_filesystem(tmpdir, [])
            paths = [f["path"] for f in files]

            self.assertIn("logo.png", paths, "Image files must be in inventory")
            self.assertIn("app.js", paths)

    def test_default_excludes_honored(self):
        """node_modules and .git should be excluded by DEFAULT_EXCLUDES."""
        with tempfile.TemporaryDirectory() as tmpdir:
            nm = Path(tmpdir) / "node_modules"
            nm.mkdir()
            (nm / "pkg.js").write_text("x", encoding="utf-8")

            git = Path(tmpdir) / ".git"
            git.mkdir()
            (git / "config").write_text("x", encoding="utf-8")

            (Path(tmpdir) / "src.py").write_text("x", encoding="utf-8")

            files = sb.walk_filesystem(tmpdir, [])
            paths = [f["path"] for f in files]

            self.assertIn("src.py", paths)
            self.assertNotIn("node_modules/pkg.js", paths)
            self.assertNotIn(".git/config", paths)


# ═════════════════════════════════════════════════════════════════════
# Bug #5: No hardcoded license filter — all valid SPDX licenses pass
# ═════════════════════════════════════════════════════════════════════

class TestNoHardcodedLicenseFilter(unittest.TestCase):
    """License elements must be created for any valid license string."""

    def test_gpl_license_creates_element(self):
        """GPL-3.0-or-later must produce a license element (not filtered out)."""
        packages = [
            {"name": "gpl-pkg", "version": "1.0", "ecosystem": "npm",
             "purl": "", "license": "GPL-3.0-or-later"},
        ]
        _, lic_elements = sb.build_package_elements(packages, "urn:spdx:test/abc", [0])

        self.assertGreater(len(lic_elements), 0, "GPL license must not be filtered out")
        lic_exprs = [e for e in lic_elements if e["@type"] == "simplelicensing_LicenseExpression"]
        self.assertEqual(lic_exprs[0]["simplelicensing_licenseExpression"], "GPL-3.0-or-later")

    def test_complex_license_expression(self):
        """Complex expressions like (MIT OR Apache-2.0) must pass through."""
        packages = [
            {"name": "dual-pkg", "version": "1.0", "ecosystem": "npm",
             "purl": "", "license": "(MIT OR Apache-2.0)"},
        ]
        _, lic_elements = sb.build_package_elements(packages, "urn:spdx:test/abc", [0])

        lic_exprs = [e for e in lic_elements if e["@type"] == "simplelicensing_LicenseExpression"]
        self.assertEqual(len(lic_exprs), 1)
        self.assertEqual(lic_exprs[0]["simplelicensing_licenseExpression"], "(MIT OR Apache-2.0)")

    def test_noassertion_filtered(self):
        """NOASSERTION, NONE, UNLICENSED should NOT create license elements."""
        for sentinel in ("NOASSERTION", "NONE", "UNLICENSED"):
            packages = [
                {"name": f"pkg-{sentinel}", "version": "1.0",
                 "ecosystem": "npm", "purl": "", "license": sentinel},
            ]
            _, lic_elements = sb.build_package_elements(packages, "urn:spdx:test/abc", [0])
            self.assertEqual(len(lic_elements), 0,
                             f"{sentinel} should be filtered out")


# ═════════════════════════════════════════════════════════════════════
# Bug #6: Manifest paths must be relative with forward slashes
# ═════════════════════════════════════════════════════════════════════

class TestManifestPathNormalization(unittest.TestCase):
    """source_manifest must be relative path with '/' separators."""

    def test_npm_manifest_path_normalized(self):
        """Package source_manifest must use forward slashes."""
        with tempfile.TemporaryDirectory() as tmpdir:
            subdir = Path(tmpdir) / "frontend"
            subdir.mkdir()
            lockfile = subdir / "package-lock.json"
            lockfile.write_text(json.dumps({
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/react": {"version": "18.0.0"}
                }
            }), encoding="utf-8")

            pkgs = sb.detect_and_parse_manifests(tmpdir)

            self.assertEqual(len(pkgs), 1)
            manifest = pkgs[0]["source_manifest"]
            self.assertNotIn("\\", manifest, "Must use forward slashes")
            self.assertFalse(os.path.isabs(manifest), "Must be relative path")
            self.assertEqual(manifest, "frontend/package-lock.json")


# ═════════════════════════════════════════════════════════════════════
# Bug #7: SPDX JSON validation — invalid JSON must be rejected
# ═════════════════════════════════════════════════════════════════════

class TestSpdxJsonValidation(unittest.TestCase):
    """extract_findings_from_spdx_json must reject non-SPDX JSON."""

    def test_rejects_arbitrary_json(self):
        """JSON without spdxVersion/SPDXID should return empty dict."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump({"name": "not-spdx", "data": [1, 2, 3]}, f)
            path = f.name

        try:
            findings = sb.extract_findings_from_spdx_json(path)
            self.assertEqual(findings, {})
        finally:
            os.unlink(path)

    def test_accepts_valid_spdx_json(self):
        """JSON with spdxVersion should be parsed."""
        spdx_doc = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "files": [
                {
                    "fileName": "./src/main.py",
                    "licenseConcluded": "MIT",
                    "copyrightText": "Copyright 2026 Author",
                    "checksums": [
                        {"algorithm": "SHA256", "checksumValue": "abc123"}
                    ]
                }
            ]
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(spdx_doc, f)
            path = f.name

        try:
            findings = sb.extract_findings_from_spdx_json(path)
            self.assertIn("src/main.py", findings)
            self.assertEqual(findings["src/main.py"]["licenses"], ["MIT"])
            self.assertEqual(findings["src/main.py"]["copyrights"], ["Copyright 2026 Author"])
            self.assertEqual(findings["src/main.py"]["checksums"]["sha256"], "abc123")
        finally:
            os.unlink(path)


# ═════════════════════════════════════════════════════════════════════
# Bug #8: Cross-platform path matching — Windows backslashes
# ═════════════════════════════════════════════════════════════════════

class TestCrossPlatformPathMatching(unittest.TestCase):
    """_match_any_pattern must handle Windows backslash paths correctly."""

    def test_backslash_path_matches_directory_pattern(self):
        """Windows path 'node_modules\\foo\\bar.js' must match 'node_modules/**'."""
        self.assertTrue(
            sb._match_any_pattern("node_modules\\foo\\bar.js", ["node_modules/**"])
        )

    def test_backslash_path_matches_extension_pattern(self):
        """Windows path 'src\\main.pyc' must match '*.pyc'."""
        self.assertTrue(
            sb._match_any_pattern("src\\main.pyc", ["*.pyc"])
        )

    def test_backslash_path_matches_glob_star_pattern(self):
        """Windows path 'images\\logo.jpg' must match '**/*.jpg'."""
        self.assertTrue(
            sb._match_any_pattern("images\\logo.jpg", ["**/*.jpg"])
        )

    def test_forward_slash_still_works(self):
        """Unix paths must continue to work correctly."""
        self.assertTrue(sb._match_any_pattern(".git/config", [".git/**"]))
        self.assertTrue(sb._match_any_pattern("build/out.js", ["build/**"]))
        self.assertFalse(sb._match_any_pattern("src/app.js", ["build/**"]))


# ═════════════════════════════════════════════════════════════════════
# Data merging — FOSSology findings properly merged into file inventory
# ═════════════════════════════════════════════════════════════════════

class TestDataMerging(unittest.TestCase):
    """merge_data must correctly attach FOSSology findings to files/packages."""

    def test_findings_merged_into_files(self):
        """FOSSology license+copyright must appear on matching files."""
        findings = {
            "src/app.js": {
                "licenses": ["MIT"],
                "copyrights": ["Copyright 2026 Test"],
                "checksums": {"sha256": "abc"},
            }
        }
        files = [
            {"path": "src/app.js", "sha256": "abc",
             "mime_type": "application/javascript", "purpose": "source",
             "licenses": [], "copyrights": []},
            {"path": "README.md", "sha256": "def",
             "mime_type": "text/markdown", "purpose": "documentation",
             "licenses": [], "copyrights": []},
        ]
        packages = []

        _, merged_files = sb.merge_data(findings, packages, files)

        self.assertEqual(merged_files[0]["licenses"], ["MIT"])
        self.assertEqual(merged_files[0]["copyrights"], ["Copyright 2026 Test"])
        # File without findings should remain empty
        self.assertEqual(merged_files[1]["licenses"], [])

    def test_fossology_fills_package_license(self):
        """Package without license from lockfile gets it from FOSSology."""
        findings = {
            "frontend/package-lock.json": {
                "licenses": ["MIT"],
                "copyrights": [],
                "checksums": {},
            }
        }
        packages = [
            {"name": "react", "version": "18.0.0", "license": "",
             "source_manifest": "frontend/package-lock.json"},
        ]
        files = []

        merged_pkgs, _ = sb.merge_data(findings, packages, files)

        self.assertEqual(merged_pkgs[0]["license"], "MIT")

    def test_existing_package_license_not_overwritten(self):
        """Package that already has license should NOT be overwritten."""
        findings = {
            "package-lock.json": {
                "licenses": ["GPL-3.0"],
                "copyrights": [],
                "checksums": {},
            }
        }
        packages = [
            {"name": "lodash", "version": "4.0.0", "license": "MIT",
             "source_manifest": "package-lock.json"},
        ]
        files = []

        merged_pkgs, _ = sb.merge_data(findings, packages, files)

        self.assertEqual(merged_pkgs[0]["license"], "MIT",
                         "Existing license must not be overwritten by FOSSology")

    def test_fossology_checksum_fills_missing(self):
        """File without SHA-256 should get it from FOSSology findings."""
        findings = {
            "src/missing_hash.py": {
                "licenses": [],
                "copyrights": [],
                "checksums": {"sha256": "from_fossology"},
            }
        }
        files = [
            {"path": "src/missing_hash.py", "sha256": "",
             "mime_type": "text/x-python", "purpose": "source",
             "licenses": [], "copyrights": []},
        ]

        _, merged_files = sb.merge_data(findings, [], files)

        self.assertEqual(merged_files[0]["sha256"], "from_fossology")


# ═════════════════════════════════════════════════════════════════════
# No project-specific code — doc_name from env/basename, not hardcoded
# ═════════════════════════════════════════════════════════════════════

class TestNoProjectSpecificCode(unittest.TestCase):
    """The builder must not contain hardcoded project names."""

    def test_doc_name_from_env_var(self):
        """doc_name should come from GITHUB_REPOSITORY env var."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out = os.path.join(tmpdir, "sbom.jsonld")
            with patch.dict(os.environ, {"GITHUB_REPOSITORY": "MyOrg/GenericRepo"}):
                sb.build(tmpdir, None, out)

            doc = json.load(open(out))
            spdx_doc = [e for e in doc["@graph"] if e.get("@type") == "SpdxDocument"][0]
            self.assertEqual(spdx_doc["name"], "MyOrg/GenericRepo")

    def test_doc_name_fallback_to_basename(self):
        """Without GITHUB_REPOSITORY, doc_name should be folder basename."""
        with tempfile.TemporaryDirectory(prefix="my-cool-project-") as tmpdir:
            out = os.path.join(tmpdir, "sbom.jsonld")
            env = os.environ.copy()
            env.pop("GITHUB_REPOSITORY", None)
            with patch.dict(os.environ, env, clear=True):
                sb.build(tmpdir, None, out)

            doc = json.load(open(out))
            spdx_doc = [e for e in doc["@graph"] if e.get("@type") == "SpdxDocument"][0]
            self.assertEqual(spdx_doc["name"], os.path.basename(tmpdir))

    def test_source_code_no_hardcoded_repo_names(self):
        """Script source must not contain hardcoded project/repo names."""
        script_path = os.path.join(os.path.dirname(__file__), "spdx3_builder.py")
        with open(script_path, "r", encoding="utf-8") as f:
            source = f.read()

        # These are project-specific strings that should NEVER appear
        forbidden = [
            "HAD-Radiology",
            "HAD-RadiologyPlus",
            "ISC OR GPL-3.0-or-later",  # old hardcoded filter
        ]
        for term in forbidden:
            self.assertNotIn(term, source,
                             f"Hardcoded project-specific string found: '{term}'")


# ═════════════════════════════════════════════════════════════════════
# SBOM structure validation — all elements conform to SPDX 3.0
# ═════════════════════════════════════════════════════════════════════

class TestSbomStructureValidation(unittest.TestCase):
    """End-to-end: generated SBOM must pass internal validation."""

    def test_all_elements_valid(self):
        """validate_element must find 0 errors on a generated SBOM."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a minimal repo structure
            (Path(tmpdir) / "README.md").write_text("# Test", encoding="utf-8")
            (Path(tmpdir) / "main.py").write_text("print('hello')", encoding="utf-8")
            out = os.path.join(tmpdir, "sbom.jsonld")
            sb.build(tmpdir, None, out)

            doc = json.load(open(out))
            errors = []
            for elem in doc["@graph"]:
                sb.validate_element(elem, errors)
            self.assertEqual(errors, [], f"Validation errors: {errors}")

    def test_all_ids_unique(self):
        """Every element in the SBOM must have a unique @id."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "a.txt").write_text("", encoding="utf-8")
            (Path(tmpdir) / "b.txt").write_text("", encoding="utf-8")
            (Path(tmpdir) / "c.txt").write_text("", encoding="utf-8")  # same content as a.txt
            out = os.path.join(tmpdir, "sbom.jsonld")
            sb.build(tmpdir, None, out)

            doc = json.load(open(out))
            ids = [e["@id"] for e in doc["@graph"]]
            self.assertEqual(len(ids), len(set(ids)),
                             f"Duplicate IDs: {[x for x in ids if ids.count(x) > 1]}")

    def test_json_ld_structure(self):
        """SBOM must have @context and @graph keys."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "test.txt").write_text("x", encoding="utf-8")
            out = os.path.join(tmpdir, "sbom.jsonld")
            sb.build(tmpdir, None, out)

            doc = json.load(open(out))
            self.assertIn("@context", doc)
            self.assertIn("@graph", doc)
            self.assertIsInstance(doc["@graph"], list)


# ═════════════════════════════════════════════════════════════════════
# Clearing decisions — policy drives annotations, not file exclusion
# ═════════════════════════════════════════════════════════════════════

class TestClearingDecisions(unittest.TestCase):
    """Clearing policy must create annotations, not filter files from SBOM."""

    def test_excluded_files_still_in_sbom(self):
        """Files matching clearing exclude patterns must exist in SBOM with EXCLUDED annotation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create files
            (Path(tmpdir) / "app.js").write_text("x", encoding="utf-8")
            img_dir = Path(tmpdir) / "images"
            img_dir.mkdir()
            (img_dir / "logo.png").write_bytes(b"\x89PNG\r\n")

            # Write clearing policy that excludes PNG files
            policy_path = os.path.join(tmpdir, "policy.json")
            with open(policy_path, "w") as f:
                json.dump({"licenses": ["MIT"], "exclude": ["**/*.png"]}, f)

            out = os.path.join(tmpdir, "sbom.jsonld")
            sb.build(tmpdir, None, out, clearing_policy_path=policy_path)

            doc = json.load(open(out))
            graph = doc["@graph"]

            # The PNG file must be in the SBOM as a software_File
            file_names = [e["name"] for e in graph if e.get("@type") == "software_File"]
            self.assertIn("images/logo.png", file_names,
                          "Excluded file must still appear in SBOM")

            # And it must have an EXCLUDED annotation
            excluded_anns = [
                e for e in graph
                if e.get("@type") == "Annotation" and "EXCLUDED" in e.get("statement", "")
            ]
            self.assertGreater(len(excluded_anns), 0, "Must have EXCLUDED annotation")

    def test_flagged_license(self):
        """License not in approved list must be FLAGGED, not silently dropped."""
        # Build a graph manually with a GPL-licensed file
        base = "urn:spdx:test/abc"
        graph = [
            {"@type": "software_File", "@id": f"{base}/File/0",
             "creationInfo": "_:creationinfo", "name": "gpl-file.c"},
            {"@type": "simplelicensing_LicenseExpression",
             "@id": f"{base}/LicenseExpression/0",
             "creationInfo": "_:creationinfo",
             "simplelicensing_licenseExpression": "GPL-3.0-or-later"},
            {"@type": "Relationship", "@id": f"{base}/LicenseRelationship/0",
             "creationInfo": "_:creationinfo",
             "from": f"{base}/File/0", "to": [f"{base}/LicenseExpression/0"],
             "relationshipType": "hasConcludedLicense"},
        ]
        policy = {"licenses": ["MIT"], "exclude": []}

        annotations, summary = sb.apply_clearing(graph, policy, base)

        self.assertEqual(len(summary["flagged"]), 1)
        self.assertIn("GPL-3.0-or-later", summary["flagged"][0]["license"])

    def test_cleared_license(self):
        """License in approved list must be CLEARED."""
        base = "urn:spdx:test/abc"
        graph = [
            {"@type": "software_Package", "@id": f"{base}/Package/foo",
             "creationInfo": "_:creationinfo", "name": "foo"},
            {"@type": "simplelicensing_LicenseExpression",
             "@id": f"{base}/LicenseExpression/0",
             "creationInfo": "_:creationinfo",
             "simplelicensing_licenseExpression": "MIT"},
            {"@type": "Relationship", "@id": f"{base}/LicenseRelationship/0",
             "creationInfo": "_:creationinfo",
             "from": f"{base}/Package/foo", "to": [f"{base}/LicenseExpression/0"],
             "relationshipType": "hasDeclaredLicense"},
        ]
        policy = {"licenses": ["MIT", "Apache-2.0"], "exclude": []}

        annotations, summary = sb.apply_clearing(graph, policy, base)

        self.assertEqual(len(summary["cleared"]), 1)
        self.assertEqual(len(summary["flagged"]), 0)


# ═════════════════════════════════════════════════════════════════════
# Maven pom.xml parsing
# ═════════════════════════════════════════════════════════════════════

class TestPomXmlParsing(unittest.TestCase):
    """parse_pom_xml must handle namespaced and non-namespaced poms."""

    def test_namespaced_pom(self):
        """Standard Maven pom with namespace must be parsed."""
        pom_content = textwrap.dedent("""\
            <?xml version="1.0"?>
            <project xmlns="http://maven.apache.org/POM/4.0.0">
                <dependencies>
                    <dependency>
                        <groupId>org.springframework</groupId>
                        <artifactId>spring-core</artifactId>
                        <version>5.3.20</version>
                    </dependency>
                </dependencies>
            </project>
        """)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".xml", delete=False, encoding="utf-8"
        ) as f:
            f.write(pom_content)
            path = f.name

        try:
            pkgs = sb.parse_pom_xml(path)
            self.assertEqual(len(pkgs), 1)
            self.assertEqual(pkgs[0]["name"], "org.springframework:spring-core")
            self.assertEqual(pkgs[0]["version"], "5.3.20")
            self.assertEqual(pkgs[0]["purl"], "pkg:maven/org.springframework/spring-core@5.3.20")
        finally:
            os.unlink(path)

    def test_property_version_cleared(self):
        """Maven property references like ${version} should be cleared."""
        pom_content = textwrap.dedent("""\
            <?xml version="1.0"?>
            <project xmlns="http://maven.apache.org/POM/4.0.0">
                <dependencies>
                    <dependency>
                        <groupId>com.example</groupId>
                        <artifactId>my-lib</artifactId>
                        <version>${project.version}</version>
                    </dependency>
                </dependencies>
            </project>
        """)
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".xml", delete=False, encoding="utf-8"
        ) as f:
            f.write(pom_content)
            path = f.name

        try:
            pkgs = sb.parse_pom_xml(path)
            self.assertEqual(pkgs[0]["version"], "")
            self.assertEqual(pkgs[0]["purl"], "")  # no PURL without version
        finally:
            os.unlink(path)


# ═════════════════════════════════════════════════════════════════════
# FOSSology TEXT report parsing
# ═════════════════════════════════════════════════════════════════════

class TestTextReportParsing(unittest.TestCase):
    """extract_findings_from_text must handle various TEXT report formats."""

    def test_simple_path_license(self):
        """Standard 'path: license' lines must be parsed."""
        content = "src/app.js: MIT\nsrc/util.js: Apache-2.0\n"
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as f:
            f.write(content)
            path = f.name

        try:
            findings = sb.extract_findings_from_text(path)
            self.assertIn("src/app.js", findings)
            self.assertEqual(findings["src/app.js"]["licenses"], ["MIT"])
            self.assertIn("src/util.js", findings)
        finally:
            os.unlink(path)

    def test_triple_colon_format(self):
        """Scanner triple-colon format 'scanner:::path:::finding' must be parsed."""
        content = "nomos:::./src/main.py:::MIT\nojo:::./src/main.py:::Apache-2.0\n"
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as f:
            f.write(content)
            path = f.name

        try:
            findings = sb.extract_findings_from_text(path)
            self.assertIn("src/main.py", findings)
            self.assertIn("MIT", findings["src/main.py"]["licenses"])
            self.assertIn("Apache-2.0", findings["src/main.py"]["licenses"])
        finally:
            os.unlink(path)

    def test_copyright_classified(self):
        """Lines starting with 'Copyright' must go to copyrights, not licenses."""
        content = "src/main.py: Copyright 2026 Author\n"
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", delete=False, encoding="utf-8"
        ) as f:
            f.write(content)
            path = f.name

        try:
            findings = sb.extract_findings_from_text(path)
            self.assertEqual(findings["src/main.py"]["copyrights"], ["Copyright 2026 Author"])
            self.assertEqual(findings["src/main.py"]["licenses"], [])
        finally:
            os.unlink(path)


# ═════════════════════════════════════════════════════════════════════
# npm lockfile v1 parsing
# ═════════════════════════════════════════════════════════════════════

class TestNpmLockfileV1(unittest.TestCase):
    """parse_npm_lockfile must handle lockfileVersion 1 format."""

    def test_v1_flat_deps(self):
        """lockfileVersion 1 with flat dependencies must be parsed."""
        lock = {
            "lockfileVersion": 1,
            "dependencies": {
                "lodash": {
                    "version": "4.17.21",
                    "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
                    "integrity": "sha512-abc123",
                },
                "@babel/core": {
                    "version": "7.20.0",
                    "resolved": "https://registry.npmjs.org/@babel/core/-/core-7.20.0.tgz",
                    "integrity": "sha512-def456",
                }
            }
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(lock, f)
            path = f.name

        try:
            pkgs = sb.parse_npm_lockfile(path)
            self.assertEqual(len(pkgs), 2)

            names = {p["name"] for p in pkgs}
            self.assertIn("lodash", names)
            self.assertIn("@babel/core", names)

            # Check scoped package PURL encoding
            babel = next(p for p in pkgs if p["name"] == "@babel/core")
            self.assertIn("%40babel", babel["purl"])
        finally:
            os.unlink(path)

    def test_v1_nested_deps(self):
        """lockfileVersion 1 with nested dependencies must recurse."""
        lock = {
            "lockfileVersion": 1,
            "dependencies": {
                "parent": {
                    "version": "1.0.0",
                    "dependencies": {
                        "child": {"version": "2.0.0"}
                    }
                }
            }
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(lock, f)
            path = f.name

        try:
            pkgs = sb.parse_npm_lockfile(path)
            names = {p["name"] for p in pkgs}
            self.assertIn("parent", names)
            self.assertIn("child", names)
        finally:
            os.unlink(path)


# ═════════════════════════════════════════════════════════════════════
# generate_base_uri — must be safe and unique
# ═════════════════════════════════════════════════════════════════════

class TestGenerateBaseUri(unittest.TestCase):
    """generate_base_uri must produce safe, unique URNs."""

    def test_special_chars_sanitized(self):
        """Special characters in doc name must be replaced."""
        uri = sb.generate_base_uri("My Org/My Repo!")
        self.assertTrue(uri.startswith("urn:spdx:"))
        self.assertNotIn(" ", uri)
        self.assertNotIn("!", uri)

    def test_unique_per_call(self):
        """Two calls with same name must produce different URIs."""
        uri1 = sb.generate_base_uri("test")
        uri2 = sb.generate_base_uri("test")
        self.assertNotEqual(uri1, uri2)


# ═════════════════════════════════════════════════════════════════════
# End-to-end build with clearing report
# ═════════════════════════════════════════════════════════════════════

class TestEndToEndWithClearing(unittest.TestCase):
    """Full pipeline: build + clearing must produce valid SBOM + report."""

    def test_build_with_clearing_policy(self):
        """End-to-end: SBOM + clearing report generated and valid."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "main.py").write_text("# MIT licensed", encoding="utf-8")
            (Path(tmpdir) / "image.png").write_bytes(b"\x89PNG\r\n")

            policy_path = os.path.join(tmpdir, "policy.json")
            with open(policy_path, "w") as f:
                json.dump({
                    "licenses": ["MIT"],
                    "exclude": ["**/*.png"]
                }, f)

            out = os.path.join(tmpdir, "out.jsonld")
            sb.build(tmpdir, None, out, clearing_policy_path=policy_path)

            # SBOM must exist and be valid JSON-LD
            self.assertTrue(os.path.exists(out))
            doc = json.load(open(out))
            self.assertIn("@context", doc)

            # Clearing report must exist
            report = out.rsplit(".", 1)[0] + "_clearing_report.txt"
            self.assertTrue(os.path.exists(report))

            # Report must contain EXCLUDED entries for PNG
            with open(report, "r", encoding="utf-8") as f:
                report_text = f.read()
            self.assertIn("EXCLUDED", report_text)

    def test_build_without_clearing_policy(self):
        """Build without clearing must still work (no annotations)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "hello.txt").write_text("hi", encoding="utf-8")
            out = os.path.join(tmpdir, "out.jsonld")
            sb.build(tmpdir, None, out)

            doc = json.load(open(out))
            annotations = [e for e in doc["@graph"] if e.get("@type") == "Annotation"]
            self.assertEqual(len(annotations), 0, "No annotations without clearing policy")


if __name__ == "__main__":
    unittest.main()
