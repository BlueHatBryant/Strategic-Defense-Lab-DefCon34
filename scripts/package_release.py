#!/usr/bin/env python3
"""Build a deterministic participant archive without complete solutions."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[1]
ARCHIVE_ROOT = "strategic-defense-lab"
EXCLUDED_PARTS = {
    ".git",
    ".github",
    ".idea",
    ".vscode",
    "__pycache__",
    "dist",
    "instructor",
    "solutions",
    "work",
    "infra",
}
EXCLUDED_NAMES = {
    ".DS_Store",
    "slides.pptx",
    "slides-outline.md",
    "build_slides.py",
    "deploy.sh",
    "cleanup.sh",
}


def should_include(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    if any(part in EXCLUDED_PARTS for part in relative.parts):
        return False
    if path.name.startswith("~$"):
        return False
    if path.suffix.lower() == ".pptx":
        return False
    if path.name.startswith("build_slides") and path.suffix == ".py":
        return False
    if path.name in EXCLUDED_NAMES or path.suffix in {".pyc", ".pyo"}:
        return False
    return path.is_file()


def release_files() -> list[Path]:
    return sorted(
        (path for path in ROOT.rglob("*") if should_include(path)),
        key=lambda path: path.relative_to(ROOT).as_posix(),
    )


def build_release(output_dir: Path | None = None) -> tuple[Path, Path, str]:
    if output_dir is None:
        output_dir = ROOT / "dist"
    output_dir.mkdir(parents=True, exist_ok=True)
    archive = output_dir / "strategic-defense-lab.zip"
    checksum_file = output_dir / "strategic-defense-lab.zip.sha256"

    with ZipFile(archive, "w", compression=ZIP_DEFLATED, compresslevel=9) as bundle:
        for path in release_files():
            relative = path.relative_to(ROOT).as_posix()
            info = ZipInfo(f"{ARCHIVE_ROOT}/{relative}")
            info.date_time = (2026, 8, 8, 0, 0, 0)
            info.compress_type = ZIP_DEFLATED
            mode = path.stat().st_mode & 0o777
            relative_path = path.relative_to(ROOT)
            if relative_path.parts[0] == "scripts" and path.suffix == ".sh":
                mode |= 0o111
            info.external_attr = (0o100000 | mode) << 16
            bundle.writestr(info, path.read_bytes())

    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    checksum_file.write_text(f"{digest}  {archive.name}\n", encoding="utf-8")
    return archive, checksum_file, digest


def main() -> int:
    sys.path.insert(0, str(ROOT / "tools"))
    import workshop

    errors = workshop.validate()
    if errors:
        for error in errors:
            print(f"FAIL: {error}", file=sys.stderr)
        return 1
    archive, checksum, digest = build_release()
    print(f"Wrote {archive}")
    print(f"Wrote {checksum}")
    print(f"SHA-256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
