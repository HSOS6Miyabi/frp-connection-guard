"""Release-archive smoke tests runnable without Rust or a platform compiler."""
import sys
from pathlib import Path
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from package_release import archive_name, write_archive
from verify_release_assets import verify_folder


class ReleaseArchiveTests(unittest.TestCase):
    def test_package_matrix_and_verify(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "config").mkdir()
            (root / "config" / "guard.toml").write_text("[server]\n")
            (root / "config" / "frps.toml").write_text("[[httpPlugins]]\n")
            (root / "README.md").write_text("test readme")
            binary = root / "binary"
            binary.write_bytes(b"binary test content")
            dist = root / "dist"
            dist.mkdir()
            import hashlib
            for platform in ("linux", "windows", "macos"):
                for arch in ("amd64", "arm64"):
                    archive = dist / archive_name("ci-42", platform, arch)
                    write_archive(archive, binary, root, platform)
                    sha256 = hashlib.sha256(archive.read_bytes()).hexdigest()
                    (dist / (archive.name + ".sha256")).write_text(f"{sha256}  {archive.name}\n")
            verify_folder(dist, "ci-42")
            archive = dist / archive_name("ci-42", "windows", "amd64")
            archive.write_bytes(archive.read_bytes() + b"tampered")
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                verify_folder(dist, "ci-42")

    def test_invalid_version(self):
        for bad in ("../unsafe", "v1", "", "a/b", "ci-bad"):
            with self.assertRaises(ValueError):
                archive_name(bad, "linux", "amd64")


if __name__ == "__main__":
    unittest.main()
