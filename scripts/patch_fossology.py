#!/usr/bin/env python3
"""
Patch FOSSology SpdxReport.py bug inside the Docker container.

Bug: package.license_concluded defaults to None but the guard check only
tests for SpdxNoAssertion() and SpdxNone(), causing TypeError when the
first allowlisted file triggers: None & LicenseSymbol.

Fix: add None to the guard tuple so it's handled like SpdxNoAssertion/SpdxNone.
"""
import pathlib
import sys

target = pathlib.Path("/bin/FoScanner/SpdxReport.py")
if not target.exists():
    print(f"ERROR: {target} not found", file=sys.stderr)
    sys.exit(1)

src = target.read_text()
old = "in (SpdxNoAssertion(), SpdxNone()):"
new = "in (None, SpdxNoAssertion(), SpdxNone()):"

if old in src:
    src = src.replace(old, new)
    target.write_text(src)
    print(f"Patched {target}: added None to license_concluded guard")
else:
    print(f"Patch target not found in {target} (already fixed or API changed)")
