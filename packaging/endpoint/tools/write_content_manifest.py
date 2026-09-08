"""Write a deterministic SHA-256 manifest for a prepared package tree."""

from __future__ import annotations

import argparse
import hashlib
import os
import sys
from pathlib import Path


def _digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def write_manifest(root: Path, output: Path) -> None:
    root = root.resolve(strict=True)
    if not root.is_dir() or root.is_symlink():
        raise ValueError("package root must be a real directory")
    output = output.resolve(strict=False)
    try:
        output.relative_to(root)
    except ValueError as exc:
        raise ValueError("content manifest must be written inside the package root") from exc
    if output.exists():
        raise ValueError("content manifest already exists")
    records: list[str] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.as_posix()):
        if path.is_symlink():
            raise ValueError("package tree must not contain symbolic links")
        if not path.is_file() or path.resolve() == output:
            continue
        relative = path.relative_to(root).as_posix()
        records.append(f"{_digest(path)} *{relative}")
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(records) + "\n")
        handle.flush()
        os.fsync(handle.fileno())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        write_manifest(args.root, args.output)
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
