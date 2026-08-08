from __future__ import annotations

import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import package_release  # noqa: E402


class ReleasePackagingTests(unittest.TestCase):
    def test_release_is_reproducible_solution_free_and_verifiable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "out"
            archive, checksum_path, first_digest = package_release.build_release(output)
            first_bytes = archive.read_bytes()
            _, _, second_digest = package_release.build_release(output)

            self.assertEqual(first_digest, second_digest)
            self.assertEqual(first_bytes, archive.read_bytes())
            self.assertEqual(first_digest, hashlib.sha256(archive.read_bytes()).hexdigest())
            self.assertIn(first_digest, checksum_path.read_text(encoding="utf-8"))

            with ZipFile(archive) as bundle:
                names = bundle.namelist()
                self.assertIn("strategic-defense-lab/README.md", names)
                self.assertFalse(any("/instructor/" in name for name in names))
                self.assertFalse(any("/solutions/" in name for name in names))
                self.assertFalse(any(name.lower().endswith(".pptx") for name in names))
                self.assertFalse(
                    any(Path(name).name.startswith("build_slides") for name in names)
                )
                self.assertFalse(any("__pycache__" in name for name in names))
                self.assertFalse(any("/infra/" in name for name in names))
                self.assertNotIn("strategic-defense-lab/scripts/deploy.sh", names)
                self.assertNotIn("strategic-defense-lab/scripts/cleanup.sh", names)
                extract_root = Path(directory) / "extracted"
                bundle.extractall(extract_root)

            completed = subprocess.run(
                [sys.executable, "tools/workshop.py", "verify"],
                cwd=extract_root / "strategic-defense-lab",
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
            self.assertIn("PASS:", completed.stdout)

            tests_completed = subprocess.run(
                [sys.executable, "tests/test_workshop.py", "-v"],
                cwd=extract_root / "strategic-defense-lab",
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(
                0,
                tests_completed.returncode,
                tests_completed.stdout + tests_completed.stderr,
            )


if __name__ == "__main__":
    unittest.main()
