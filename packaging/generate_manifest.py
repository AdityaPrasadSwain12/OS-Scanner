"""Create a deterministic SHA-256 release manifest for later detached signing."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifacts", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.artifacts.resolve(strict=True)
    output = args.output.resolve()
    files = [path for path in sorted(root.rglob("*")) if path.is_file() and path != output]
    manifest = {
        "algorithm": "sha256",
        "files": [
            {"path": path.relative_to(root).as_posix(), "sha256": digest(path)} for path in files
        ],
    }
    output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

