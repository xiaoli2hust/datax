from __future__ import annotations

import unittest
from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = REPOSITORY_ROOT / ".github/workflows/windows-hosted-preflight.yml"
REQUIREMENTS_PATH = REPOSITORY_ROOT / (
    "scripts/acceptance/windows-hosted-preflight.requirements.lock"
)
CHECKOUT_ACTION = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
PYTHON_ACTION = "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97"
NSIS_ARCHIVE_URL = (
    "https://sourceforge.net/projects/nsis/files/NSIS%203/3.11/"
    "nsis-3.11.zip/download"
)
NSIS_ARCHIVE_SHA256 = "c7d27f780ddb6cffb4730138cd1591e841f4b7edb155856901cdf5f214394fa1"


class WindowsHostedPreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = WORKFLOW_PATH.read_text(encoding="utf-8")
        cls.workflow = yaml.load(cls.raw, Loader=yaml.BaseLoader)
        cls.job = cls.workflow["jobs"]["native-installer-preflight"]

    def test_non_release_triggers_are_limited_to_normal_development_events(self) -> None:
        triggers = self.workflow["on"]
        self.assertEqual(set(triggers), {"pull_request", "push", "workflow_dispatch"})
        self.assertEqual(triggers["push"]["branches"], ["main", "agent/**"])
        self.assertNotIn("tags", triggers["push"])
        self.assertNotIn("pull_request_target", self.raw)
        self.assertNotIn("workflow_run", self.raw)
        self.assertNotIn("schedule", self.raw)

    def test_hosted_job_has_no_release_authority_or_artifact_egress(self) -> None:
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        self.assertEqual(set(self.workflow["jobs"]), {"native-installer-preflight"})
        self.assertEqual(self.job["permissions"], {"contents": "read"})
        self.assertEqual(self.job["runs-on"], "windows-2025")
        self.assertEqual(self.job["if"], "github.ref_type != 'tag'")
        self.assertNotIn("environment", self.workflow)
        self.assertNotIn("environment", self.job)

        lowered = self.raw.lower()
        for forbidden in (
            "environment",
            "id-token",
            "attestations",
            "secrets:",
            "secrets.",
            "cache:",
            "actions/upload-artifact",
            "actions/download-artifact",
            "gh release",
            "softprops/action-gh-release",
            "publish",
            "signtool",
            "authenticode",
            "signing",
            "pfx",
            "certificate",
            "docker ",
            "docker.exe",
            "wsl ",
            "wsl.exe",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, lowered)

    def test_native_build_and_nsis_compilation_are_deliberately_non_release(self) -> None:
        actions = [
            step.get("uses")
            for step in self.job["steps"]
            if step.get("uses") is not None
        ]
        self.assertEqual(actions, [CHECKOUT_ACTION, PYTHON_ACTION])
        python_step = next(
            step for step in self.job["steps"] if step.get("uses") == PYTHON_ACTION
        )
        self.assertEqual(python_step["with"], {"python-version": "3.12.10"})
        self.assertIn("rustup toolchain install 1.97.0", self.raw)
        self.assertIn("cargo test --locked", self.raw)
        self.assertIn("cargo build --locked --release", self.raw)
        self.assertIn('"DES_RELEASE_MANIFEST_SHA256"', self.raw)
        self.assertIn('Remove-Item -LiteralPath "Env:$name"', self.raw)
        self.assertIn(NSIS_ARCHIVE_URL, self.raw)
        self.assertIn(NSIS_ARCHIVE_SHA256, self.raw)
        self.assertNotIn("Invoke-WebRequest", self.raw)
        self.assertIn('Join-Path $env:SystemRoot "System32\\curl.exe"', self.raw)
        for required_curl_option in (
            '"--disable"',
            '"--fail"',
            '"--location"',
            '"--proto-redir"',
            '"=https"',
            '"--tlsv1.2"',
            '"--output"',
        ):
            with self.subTest(required_curl_option=required_curl_option):
                self.assertIn(required_curl_option, self.raw)
        self.assertIn("Get-FileHash -LiteralPath $archive -Algorithm SHA256", self.raw)
        self.assertIn("Expand-Archive", self.raw)
        self.assertIn("nsis-3.11\\makensis.exe", self.raw)
        self.assertIn("nonrelease-installer-preflight.exe", self.raw)
        self.assertIn("deliberately non-release preflight input", self.raw)
        self.assertIn("Remove all generated non-release inputs and output", self.raw)
        self.assertIn(
            "Remove-Item -LiteralPath $preflightRoot -Recurse -Force",
            self.raw,
        )

    def test_static_check_dependency_is_minimal_hash_locked_and_windows_compatible(self) -> None:
        requirements = REQUIREMENTS_PATH.read_text(encoding="utf-8")
        self.assertIn(
            "-r scripts/acceptance/windows-hosted-preflight.requirements.lock",
            self.raw,
        )
        self.assertIn("--only-binary=:all: --require-hashes", self.raw)
        self.assertNotIn("backend/requirements-dev.lock", self.raw)
        self.assertIn(
            "scripts/acceptance/windows-hosted-preflight.requirements.lock",
            self.workflow["on"]["pull_request"]["paths"],
        )
        self.assertIn(
            "scripts/acceptance/windows-hosted-preflight.requirements.lock",
            self.workflow["on"]["push"]["paths"],
        )

        non_comment_lines = [
            line.strip()
            for line in requirements.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertEqual(
            non_comment_lines,
            [
                "pyyaml==6.0.3 \\",
                "--hash=sha256:5fcd34e47f6e0b794d17de1b4ff496c00986e1c83f7ab2fb8fcfe9616ff7477b",
            ],
        )
        self.assertNotIn("uvloop", "\n".join(non_comment_lines).lower())


if __name__ == "__main__":
    unittest.main()
