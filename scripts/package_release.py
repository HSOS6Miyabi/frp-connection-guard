#!/usr/bin/env python3
"""Build a deterministic, platform-specific release archive and SHA-256 sidecar."""

import argparse
import hashlib
import io
from pathlib import Path
import re
import tarfile
import zipfile

APP = "frp-connection-guard"
PLATFORMS = {"linux", "windows", "macos"}
ARCHITECTURES = {"amd64", "arm64"}
VERSION_RE = re.compile(r"(?:v\d+\.\d+\.\d+(?:[-+][a-zA-Z0-9.]+)?|ci-\d+)\Z")


def archive_name(version: str, platform: str, architecture: str) -> str:
    if not VERSION_RE.fullmatch(version):
        raise ValueError("version must be a version tag (vX.Y.Z) or CI build ID (ci-N)")
    if platform not in PLATFORMS or architecture not in ARCHITECTURES:
        raise ValueError("unsupported platform or architecture")
    extension = "zip" if platform == "windows" else "tar.gz"
    return f"{APP}-{version}-{platform}-{architecture}.{extension}"


def write_archive(destination: Path, binary: Path, root: Path, platform: str) -> None:
    filename = f"{APP}.exe" if platform == "windows" else APP
    sources = [
        (binary, filename),
        (root / "config" / "guard.toml", "config/guard.toml"),
        (root / "config" / "frps.toml", "config/frps.toml"),
        (root / "README.md", "README.md"),
    ]
    for source, _ in sources:
        if not source.is_file():
            raise FileNotFoundError(f"required release file is missing: {source}")

    directory = destination.name.removesuffix(".zip").removesuffix(".tar.gz")
    if platform == "windows":
        with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as output:
            for source, relative_path in sources:
                info = zipfile.ZipInfo(f"{directory}/{relative_path}", date_time=(1980, 1, 1, 0, 0, 0))
                info.create_system = 3
                info.external_attr = ((0o755 if relative_path == filename else 0o644) << 16)
                info.compress_type = zipfile.ZIP_DEFLATED
                output.writestr(info, source.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    else:
        with tarfile.open(destination, "w:gz", compresslevel=9, format=tarfile.PAX_FORMAT) as output:
            for source, relative_path in sources:
                data = source.read_bytes()
                info = tarfile.TarInfo(f"{directory}/{relative_path}")
                info.size = len(data)
                info.mode = 0o755 if relative_path == filename else 0o644
                info.mtime = 0
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                output.addfile(info, io.BytesIO(data))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--platform", choices=sorted(PLATFORMS), required=True)
    parser.add_argument("--arch", choices=sorted(ARCHITECTURES), required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--output", type=Path, default=Path("dist"))
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    archive = args.output / archive_name(args.version, args.platform, args.arch)
    write_archive(archive, args.binary, args.root, args.platform)
    with archive.open("rb") as source:
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    checksum = archive.with_name(archive.name + ".sha256")
    checksum.write_text(f"{digest}  {archive.name}\n", encoding="ascii")
    print(f"Packaged {archive} ({archive.stat().st_size} bytes); SHA-256 {digest}")


if __name__ == "__main__":
    main()
