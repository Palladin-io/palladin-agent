#!/usr/bin/env python3
"""Build the deterministic skills-only archive used for Codex submission review."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import sys
import tempfile
from typing import Final, NoReturn
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo


ARCHIVE_ROOT: Final = "palladin-agent"
REPOSITORY_ROOT: Final = Path(__file__).resolve().parents[3]
PLUGIN_ROOT: Final = (
    REPOSITORY_ROOT / "plugins/palladin-agent/targets/codex/palladin-agent"
)
MANIFEST_PATH: Final = ".codex-plugin/plugin.json"
EXCLUDED_NAMES: Final = frozenset({".mcp.json", ".app.json"})
FIXED_TIMESTAMP: Final = (1980, 1, 1, 0, 0, 0)


def fail(message: str) -> NoReturn:
    raise RuntimeError(message)


def collect_entries() -> dict[str, bytes]:
    entries: dict[str, bytes] = {}
    for path in sorted(PLUGIN_ROOT.rglob("*")):
        if path.is_symlink():
            fail(f"submission source contains a symbolic link: {path}")
        if path.is_dir():
            continue
        if not path.is_file():
            fail(f"submission source contains a non-regular file: {path}")

        relative_path = path.relative_to(PLUGIN_ROOT)
        if relative_path.name in EXCLUDED_NAMES:
            continue

        archive_path = PurePosixPath(ARCHIVE_ROOT, *relative_path.parts).as_posix()
        content = path.read_bytes()
        if relative_path.as_posix() == MANIFEST_PATH:
            manifest = json.loads(content)
            manifest.pop("mcpServers", None)
            manifest.pop("apps", None)
            version = manifest.get("version")
            if isinstance(version, str) and "+" in version:
                manifest["version"] = version.split("+", 1)[0]
            content = f"{json.dumps(manifest, indent=2)}\n".encode("utf-8")
        entries[archive_path] = content
    return entries


def write_archive(path: Path, entries: dict[str, bytes]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        fail(f"refusing to replace a symbolic-link archive: {path}")

    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    os.close(descriptor)
    temporary_path = Path(temporary_name)
    try:
        with ZipFile(temporary_path, "w", compression=ZIP_DEFLATED, compresslevel=9) as archive:
            for name, content in sorted(entries.items()):
                info = ZipInfo(name, FIXED_TIMESTAMP)
                info.compress_type = ZIP_DEFLATED
                info.create_system = 3
                info.external_attr = 0o100644 << 16
                archive.writestr(info, content, compress_type=ZIP_DEFLATED, compresslevel=9)
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def verify_archive(path: Path) -> dict[str, object]:
    with ZipFile(path, "r") as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            fail("submission archive contains duplicate entries")
        if not names:
            fail("submission archive is empty")
        if any(PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts for name in names):
            fail("submission archive contains an unsafe path")

        roots = {PurePosixPath(name).parts[0] for name in names}
        if roots != {ARCHIVE_ROOT}:
            fail("submission archive must contain exactly one Palladin plugin root")
        if any(PurePosixPath(name).name in EXCLUDED_NAMES for name in names):
            fail("submission archive contains local MCP or app configuration")

        manifest_archive_path = f"{ARCHIVE_ROOT}/{MANIFEST_PATH}"
        if manifest_archive_path not in names:
            fail("submission archive is missing the Codex plugin manifest")
        if not any(
            name.startswith(f"{ARCHIVE_ROOT}/skills/") and name.endswith("/SKILL.md")
            for name in names
        ):
            fail("submission archive is missing a skill")

        manifest = json.loads(archive.read(manifest_archive_path))
        if "mcpServers" in manifest or "apps" in manifest:
            fail("skills-only manifest still declares MCP servers or apps")

    return {
        "archive": str(path),
        "entries": names,
        "manifestKeys": sorted(manifest.keys()),
        "manifestVersion": manifest.get("version"),
        "root": ARCHIVE_ROOT,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
    }


def main(arguments: list[str]) -> int:
    if len(arguments) > 1:
        print("usage: package-codex-skills-only.py [OUTPUT.zip]", file=sys.stderr)
        return 2

    output = (
        Path(arguments[0]).expanduser()
        if arguments
        else REPOSITORY_ROOT / "dist/plugins/palladin-agent-codex-skills-only.zip"
    )
    if output.suffix.lower() != ".zip":
        fail("submission output must use the .zip extension")

    write_archive(output, collect_entries())
    print(json.dumps(verify_archive(output), sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1) from error
