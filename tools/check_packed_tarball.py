#!/usr/bin/env python3
"""The packed npm tarball, searched as tools/check_public_boundary.py searches a tracked file.

    python tools/check_packed_tarball.py TARBALL

The tarball `npm pack` writes is the file a release attaches, and it carries text no tracked file
holds as such: the compiled modules, their declarations, and the source maps, whose sourcesContent
holds the text of src/. The release workflow runs this over the tarball before it sums the files.

Every member must be a directory or a regular file under package/, and every file must be text
(UTF-8 with no control character but tab, line feed and carriage return) that holds none of the
needles tools/public_boundary.json names, no encoded block, and no literal code point that prints
as nothing. Those checks are the ones of check_public_boundary.py, imported from beside this file.
Its clearance routes for a file that is not text are not used: the package carries no such file,
so one is reported. Citations of tests are not read, because the package carries no tests.
test/packed-tarball.test.ts runs this over planted tarballs, one per finding.

Exit codes: 0 cleared, 1 a finding, 2 the tarball cannot be read.
"""

from __future__ import annotations

import importlib.util
import sys
import tarfile
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
PREFIX = "package"


def _boundary():
    """tools/check_public_boundary.py, loaded from beside this file."""
    spec = importlib.util.spec_from_file_location("check_public_boundary", TOOLS / "check_public_boundary.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check(tarball: Path) -> list[str]:
    """Every finding over the members of ``tarball``; an empty list when it is cleared."""
    boundary = _boundary()
    config = boundary.load_config(TOOLS.parent)
    needles = list(dict.fromkeys(needle for name in config["needle_lists"] for needle in boundary.NEEDLE_LISTS[name]))
    failures: list[str] = []
    files = 0
    with tarfile.open(tarball, "r:gz") as archive:
        for member in archive.getmembers():
            name = member.name
            parts = name.split("/")
            if parts[0] != PREFIX or any(part in ("", ".", "..") for part in parts[1:]):
                failures.append(f"{name}: not a path under {PREFIX}/")
                continue
            if member.isdir():
                continue
            if not member.isfile():
                failures.append(f"{name}: not a regular file or a directory")
                continue
            files += 1
            blob = archive.extractfile(member).read()
            text = boundary.text_of(blob)
            if text is None:
                failures.append(f"not text, so not cleared: {name}")
                continue
            failures += boundary.Clearing.search(name, text, needles)
            failures += boundary.invisible_failures(name, text)
    if files == 0:
        failures.append(f"{tarball.name} holds no file; nothing was scanned")
    return failures


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python tools/check_packed_tarball.py TARBALL", file=sys.stderr)
        return 2
    tarball = Path(args[0])
    try:
        failures = check(tarball)
    except (OSError, tarfile.TarError, ValueError) as exc:
        print(f"{tarball} cannot be checked ({exc})", file=sys.stderr)
        return 2
    for failure in failures:
        print(failure)
    if failures:
        return 1
    print("packed_tarball_ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
