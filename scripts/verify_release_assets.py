#!/usr/bin/env python3
"""Verify that all six release archives and their checksums are present and usable."""

import argparse
import hashlib
from pathlib import Path
import tarfile
import zipfile

from package_release import APP, ARCHITECTURES, PLATFORMS, archive_name


def verify_folder(directory: Path, version: str) -> None:
    expected = {archive_name(version, platform, arch) for platform in PLATFORMS for arch in ARCHITECTURES}
    names = {path.name for path in directory.iterdir() if path.is_file()}
    required = expected | {name + ".sha256" for name in expected}
    if names != required:
        raise ValueError(f"release assets mismatch: missing={sorted(required - names)}, extra={sorted(names - required)}")

    for name in sorted(expected):
        archive = directory / name
        with archive.open("rb") as source:
            digest = hashlib.file_digest(source, "sha256").hexdigest()
        expected_checksum = f"{digest}  {name}\n"
        if (directory / (name + ".sha256")).read_text(encoding="ascii") != expected_checksum:
            raise ValueError(f"SHA-256 mismatch: {name}")

        platform = "windows" if name.endswith(".zip") else ("macos" if "-macos-" in name else "linux")
        filename = APP + (".exe" if platform == "windows" else "")
        folder = name.removesuffix(".zip").removesuffix(".tar.gz")
        expected_files = {
            f"{folder}/{filename}",
            f"{folder}/config/guard.toml",
            f"{folder}/config/frps.toml",
            f"{folder}/README.md",
        }
        if platform == "windows":
            with zipfile.ZipFile(archive) as zipped:
                assert zipped.testzip() is None, f"invalid ZIP payload: {name}"
                members = set(zipped.namelist())
        else:
            with tarfile.open(archive, "r:gz") as tarred:
                members = {member.name for member in tarred.getmembers()}
                binary = tarred.getmember(f"{folder}/{filename}")
                if binary.mode & 0o111 == 0:
                    raise ValueError(f"binary executable bit missing in {name}")
        if members != expected_files:
            raise ValueError(f"archive members mismatch for {name}: {members ^ expected_files}")
        print(f"PASS: {name}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--directory", type=Path, default=Path("dist"))
    args = parser.parse_args()
    verify_folder(args.directory, args.version)


if __name__ == "__main__":
    main()
