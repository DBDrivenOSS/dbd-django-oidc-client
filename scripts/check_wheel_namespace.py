"""Verify the built wheel keeps the PEP 420 ``dbd`` namespace intact.

Fails if ``dbd/oidc_client/`` is missing, or if a ``dbd/__init__.py`` snuck in.
A stray ``__init__.py`` would turn the namespace package into a regular package,
breaking co-installation alongside the unrelated ``dbd`` distribution on PyPI.

Run after ``uv build`` (expects a wheel in ``dist/``).
"""

import glob
import sys
import zipfile

wheels = sorted(glob.glob("dist/*.whl"))
if not wheels:
    sys.exit("FAIL: no wheel found in dist/ (run `uv build` first)")

wheel = wheels[-1]
names = zipfile.ZipFile(wheel).namelist()

has_pkg = any(name.startswith("dbd/oidc_client/") for name in names)
has_init = any(name == "dbd/__init__.py" for name in names)

print(f"wheel: {wheel}")
print(f"dbd/oidc_client/ present: {has_pkg}")
print(f"dbd/__init__.py present:  {has_init}")

if not has_pkg:
    sys.exit("FAIL: dbd/oidc_client/ missing from wheel")

if has_init:
    sys.exit("FAIL: dbd/__init__.py present - PEP 420 namespace broken")

print("OK: PEP 420 namespace intact")
