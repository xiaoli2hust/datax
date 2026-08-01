from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("verify_anonymous_image_pulls.py")
KEYS = (
    ("DES_POSTGRES_IMAGE", "postgres"),
    ("DES_API_IMAGE", "ghcr.io/xiaoli2hust/datax-studio-api"),
    (
        "DES_EGRESS_GUARD_IMAGE",
        "ghcr.io/xiaoli2hust/datax-studio-egress-guard",
    ),
    ("DES_WORKER_IMAGE", "ghcr.io/xiaoli2hust/datax-studio-worker"),
    ("DES_WEB_IMAGE", "ghcr.io/xiaoli2hust/datax-studio-web"),
)


def _write_lock(path: Path, *, mutable: bool = False) -> None:
    digest = "a" * 64
    lines = []
    for key, repository in KEYS:
        suffix = ":latest" if mutable and key == "DES_WEB_IMAGE" else f"@sha256:{digest}"
        lines.append(f"{key}={repository}{suffix}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _write_fake_docker(path: Path) -> None:
    path.write_text(
        """#!/usr/bin/env python3
import json
import os
import pathlib
import sys

config = pathlib.Path(os.environ["DOCKER_CONFIG"])
if json.loads((config / "config.json").read_text()) != {"auths": {}}:
    raise SystemExit(91)
if os.environ.get("DOCKER_AUTH_CONFIG") or os.environ.get("REGISTRY_AUTH_FILE"):
    raise SystemExit(92)
with pathlib.Path(os.environ["FAKE_DOCKER_LOG"]).open("a", encoding="utf-8") as stream:
    stream.write(json.dumps({"args": sys.argv[1:], "config": str(config)}) + "\\n")
failure = os.environ.get("FAKE_DOCKER_FAIL_KEY")
if failure and failure in sys.argv[-1]:
    raise SystemExit(93)
""",
        encoding="utf-8",
    )
    path.chmod(0o755)


class AnonymousImagePullTests(unittest.TestCase):
    def test_pulls_exact_digest_set_with_fresh_empty_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image_lock = root / "images.release.env"
            evidence = root / "anonymous-image-pulls.json"
            fake_docker = root / "docker"
            log = root / "docker.log"
            _write_lock(image_lock)
            _write_fake_docker(fake_docker)
            environment = os.environ.copy()
            environment["FAKE_DOCKER_LOG"] = str(log)
            environment["DOCKER_AUTH_CONFIG"] = '{"auths":{"forbidden":{}}}'
            environment["REGISTRY_AUTH_FILE"] = str(root / "forbidden-auth.json")

            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--images",
                    str(image_lock),
                    "--evidence",
                    str(evidence),
                    "--docker",
                    str(fake_docker),
                ],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual(len(calls), 5)
            self.assertEqual(len({call["config"] for call in calls}), 1)
            self.assertNotEqual(calls[0]["config"], environment.get("DOCKER_CONFIG"))
            for call, (_, repository) in zip(calls, KEYS, strict=True):
                self.assertEqual(
                    call["args"][:5],
                    ["image", "pull", "--platform", "linux/amd64", "--quiet"],
                )
                self.assertRegex(
                    call["args"][5],
                    rf"^{repository}@sha256:[0-9a-f]{{64}}$",
                )

            document = json.loads(evidence.read_text(encoding="utf-8"))
            self.assertEqual(document["result"], "PASS")
            self.assertFalse(document["registry_credentials_used"])
            self.assertEqual(document["docker_config_mode"], "EPHEMERAL_EMPTY")
            self.assertEqual(
                [image["key"] for image in document["images"]],
                [key for key, _ in KEYS],
            )

    def test_failed_pull_writes_no_success_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image_lock = root / "images.release.env"
            evidence = root / "anonymous-image-pulls.json"
            fake_docker = root / "docker"
            log = root / "docker.log"
            _write_lock(image_lock)
            _write_fake_docker(fake_docker)
            environment = os.environ.copy()
            environment["FAKE_DOCKER_LOG"] = str(log)
            environment["FAKE_DOCKER_FAIL_KEY"] = "datax-studio-worker"

            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--images",
                    str(image_lock),
                    "--evidence",
                    str(evidence),
                    "--docker",
                    str(fake_docker),
                ],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(evidence.exists())
            self.assertNotIn("auths", completed.stderr)

    def test_mutable_reference_is_rejected_before_docker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image_lock = root / "images.release.env"
            evidence = root / "anonymous-image-pulls.json"
            fake_docker = root / "docker"
            log = root / "docker.log"
            _write_lock(image_lock, mutable=True)
            _write_fake_docker(fake_docker)
            environment = os.environ.copy()
            environment["FAKE_DOCKER_LOG"] = str(log)

            completed = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--images",
                    str(image_lock),
                    "--evidence",
                    str(evidence),
                    "--docker",
                    str(fake_docker),
                ],
                env=environment,
                capture_output=True,
                text=True,
                check=False,
            )

            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(log.exists())
            self.assertFalse(evidence.exists())


if __name__ == "__main__":
    unittest.main()
