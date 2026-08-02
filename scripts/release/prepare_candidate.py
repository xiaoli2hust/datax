#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import tomllib

SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
POSITIVE_INTEGER = re.compile(r"^[1-9][0-9]*$")
EXPECTED_REPOSITORY = "xiaoli2hust/datax"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate a candidate release identity and write its context.",
    )
    parser.add_argument("--event-name", required=True)
    parser.add_argument("--ref-name", required=True)
    parser.add_argument("--ref-type", required=True)
    parser.add_argument("--manual-version", default="")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--run-attempt", required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    return parser.parse_args()


def _candidate_version(args: argparse.Namespace) -> str:
    if args.event_name == "push":
        if args.ref_type != "tag":
            raise ValueError("push candidates must be triggered by a tag")
        match = re.fullmatch(r"v(.+)", args.ref_name)
        if match is None or SEMVER.fullmatch(match.group(1)) is None:
            raise ValueError("release tags must be exactly v<major>.<minor>.<patch>")
        return match.group(1)
    if args.event_name == "workflow_dispatch":
        if args.ref_type != "branch" or args.ref_name != "main":
            raise ValueError("manual candidates must run from the main branch")
        if SEMVER.fullmatch(args.manual_version) is None:
            raise ValueError("manual version must be exactly <major>.<minor>.<patch>")
        return args.manual_version
    raise ValueError("unsupported candidate trigger")


def _git_output(repository_root: Path, *arguments: str) -> str:
    return subprocess.check_output(
        ["git", *arguments],
        cwd=repository_root,
        text=True,
    ).strip()


def main() -> int:
    args = _parse_args()
    repository_root = Path(__file__).resolve().parents[2]
    if args.repository.casefold() != EXPECTED_REPOSITORY:
        raise ValueError(
            f"candidate publishing is restricted to {EXPECTED_REPOSITORY}"
        )
    if COMMIT.fullmatch(args.commit) is None:
        raise ValueError("candidate commit must be a lowercase 40-character SHA")
    if (
        POSITIVE_INTEGER.fullmatch(args.run_id) is None
        or POSITIVE_INTEGER.fullmatch(args.run_attempt) is None
    ):
        raise ValueError("workflow run id and attempt must be positive integers")
    checked_out_commit = _git_output(repository_root, "rev-parse", "HEAD")
    if checked_out_commit != args.commit:
        raise ValueError("checked-out commit does not match the workflow identity")
    if subprocess.run(
        ["git", "diff", "--quiet", "HEAD", "--"],
        cwd=repository_root,
        check=False,
    ).returncode:
        raise ValueError("tracked files differ from the candidate commit")

    version = _candidate_version(args)
    cargo_manifest = repository_root / "desktop" / "windows" / "Cargo.toml"
    with cargo_manifest.open("rb") as stream:
        launcher_version = str(tomllib.load(stream)["package"]["version"])
    if version != launcher_version:
        raise ValueError(
            f"candidate version {version} does not match Launcher {launcher_version}"
        )

    args.output_directory.mkdir(parents=True, exist_ok=False)
    artifact_suffix = (
        f"{version}-{args.commit[:12]}"
        f"-run-{args.run_id}-attempt-{args.run_attempt}"
    )
    release_candidate = f"{version}-{args.commit[:12]}"
    context = {
        "schema_version": "1.0",
        "artifact_kind": "WINDOWS_LOCAL_CANDIDATE",
        "candidate_only": True,
        "public_release_created": False,
        "repository": EXPECTED_REPOSITORY,
        "git_commit": args.commit,
        "git_ref_name": args.ref_name,
        "git_ref_type": args.ref_type,
        "trigger": args.event_name,
        "version": version,
        "release_candidate": release_candidate,
        "image_tag": f"candidate-{version}-{args.commit[:12]}",
        "workflow_run_id": args.run_id,
        "workflow_run_attempt": args.run_attempt,
        "workflow_run_url": (
            f"https://github.com/{EXPECTED_REPOSITORY}/actions/runs/{args.run_id}"
        ),
        "discovery_gate": "NOT_EVIDENCED",
        "windows_e2e_status": "NOT_RUN",
        "real_datax_e2e_status": "NOT_RUN_BY_THIS_WORKFLOW",
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    context_path = args.output_directory / "release-context.json"
    context_path.write_text(
        json.dumps(context, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    with args.github_output.open("a", encoding="utf-8") as stream:
        stream.write(f"version={version}\n")
        stream.write(f"release_candidate={release_candidate}\n")
        stream.write(f"image_tag={context['image_tag']}\n")
        stream.write(f"artifact_suffix={artifact_suffix}\n")
        stream.write(f"evidence_directory={args.output_directory}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
