"""Fail closed when the vendored DataX tree differs from the upstream lock."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

SHA1 = re.compile(r"^[a-f0-9]{40}$")


def _git(repo: Path, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *arguments],
        check=check,
        capture_output=True,
        text=True,
        timeout=30,
    )


def main() -> int:
    repo = Path(__file__).resolve().parents[1]
    lock_path = repo / "runtime" / "upstream.lock.json"
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        expected_tree = lock["source_tree"]
        if SHA1.fullmatch(expected_tree) is None:
            raise ValueError("source_tree must be a lowercase Git SHA-1")
        actual_tree = _git(
            repo,
            "rev-parse",
            "HEAD:third_party/alibaba-datax",
        ).stdout.strip()
        if actual_tree != expected_tree:
            raise ValueError("committed vendored DataX tree does not match source_tree")
        tracked_diff = _git(
            repo,
            "diff",
            "--quiet",
            "HEAD",
            "--",
            "third_party/alibaba-datax",
            check=False,
        )
        if tracked_diff.returncode != 0:
            raise ValueError("vendored DataX contains uncommitted tracked changes")
        untracked = _git(
            repo,
            "ls-files",
            "--others",
            "--exclude-standard",
            "--",
            "third_party/alibaba-datax",
        ).stdout.strip()
        if untracked:
            raise ValueError("vendored DataX contains untracked files")
        source_manifest = repo / "runtime" / lock["source_manifest"]
        manifest_sha256 = hashlib.sha256(source_manifest.read_bytes()).hexdigest()
        if manifest_sha256 != lock["source_manifest_sha256"]:
            raise ValueError("upstream source manifest hash does not match the lock")
        manifest_lines = source_manifest.read_text(encoding="utf-8").splitlines()
        if len(manifest_lines) != lock["source_file_count"]:
            raise ValueError("upstream source manifest file count does not match the lock")
        for relative_path in lock["required_files"]:
            if not (repo / "third_party" / "alibaba-datax" / relative_path).is_file():
                raise ValueError(f"required upstream file is missing: {relative_path}")
    except (
        KeyError,
        OSError,
        UnicodeError,
        json.JSONDecodeError,
        subprocess.SubprocessError,
        ValueError,
    ) as exc:
        print(
            json.dumps(
                {"ready": False, "code": "UPSTREAM_SOURCE_MISMATCH", "detail": str(exc)},
                ensure_ascii=False,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(
        json.dumps(
            {
                "ready": True,
                "code": "UPSTREAM_SOURCE_LOCKED",
                "commit": lock["commit"],
                "tree": actual_tree,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
