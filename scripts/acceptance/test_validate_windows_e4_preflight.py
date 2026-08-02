from __future__ import annotations

import copy
import json
import re
import tempfile
import unittest
from pathlib import Path

from scripts.acceptance.validate_windows_e4_preflight import (
    EXPECTED_CHECK_IDS,
    validate_windows_e4_preflight,
    validate_windows_e4_preflight_file,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_PATH = REPOSITORY_ROOT / "docs/contracts/windows-e4-preflight.v1.schema.json"
POWERSHELL_PATH = REPOSITORY_ROOT / "scripts/acceptance/windows_e4_preflight.ps1"
CI_WORKFLOW_PATH = REPOSITORY_ROOT / ".github/workflows/ci.yml"
SETUP_SHA256 = "a" * 64
LAUNCHER_SHA256 = "b" * 64
SIGNER_SHA256 = "c" * 64


def _checks(*, blocked: set[str] | None = None) -> list[dict[str, str]]:
    blocked = blocked or set()
    return [
        {
            "check_id": check_id,
            "result": "BLOCKED" if check_id in blocked else "PASS",
            "detail": f"{check_id} observation",
        }
        for check_id in sorted(EXPECTED_CHECK_IDS)
    ]


def ready_document() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "artifact_kind": "WINDOWS_E4_HARNESS_PREFLIGHT",
        "local_preflight_result": "READY",
        "e4_result": "NOT_RUN",
        "release_approved": False,
        "captured_at": "2026-08-02T00:00:00Z",
        "release_candidate": "0.1.0-dddddddddddd",
        "commit_sha": "d" * 40,
        "harness_version": "windows-e4-preflight/v1",
        "baseline": {
            "baseline_id": "win11-golden-20260802",
            "independently_verified": False,
        },
        "runner": {
            "runner_id": "windows-e4-local-observation",
            "self_hosted_registration_verified": False,
        },
        "windows": {
            "edition": "Windows 11",
            "product_type": "CLIENT",
            "build": "26100",
            "architecture": "X86_64",
            "secure_boot_enabled": True,
            "virtualization_firmware_enabled": True,
            "hypervisor_present": True,
        },
        "docker": {
            "ambient_context_absent": True,
            "wsl_default_version": 2,
            "wsl_status_available": True,
            "desktop_install_detected": True,
            "engine_available": True,
            "server_os": "linux",
            "server_architecture": "amd64",
            "compose_version": "v2.39.4-desktop.1",
        },
        "candidate": {
            "expected_signer_certificate_der_sha256": SIGNER_SHA256,
            "setup": {
                "file_name": "DataX-Enterprise-Studio-Setup-0.1.0-x64.exe",
                "sha256": SETUP_SHA256,
                "expected_sha256": SETUP_SHA256,
                "hash_matches": True,
                "authenticode_status": "VALID",
                "signer_certificate_der_sha256": SIGNER_SHA256,
                "signer_matches": True,
                "timestamp_present": True,
            },
            "launcher": {
                "file_name": "launcher.exe",
                "sha256": LAUNCHER_SHA256,
                "expected_sha256": LAUNCHER_SHA256,
                "hash_matches": True,
                "authenticode_status": "VALID",
                "signer_certificate_der_sha256": SIGNER_SHA256,
                "signer_matches": True,
                "timestamp_present": True,
            },
        },
        "product_state_absent": True,
        "checks": _checks(),
        "limitations": [
            "Local observations do not prove an approved golden-image restore.",
            "The local script does not prove protected runner registration.",
            "The local script does not execute an E4 scenario or approve a release.",
        ],
    }


class ValidateWindowsE4PreflightTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))

    def test_accepts_ready_observation_with_parent_level_expected_signer(self) -> None:
        document = ready_document()

        result = validate_windows_e4_preflight(document=document, schema=self.schema)

        self.assertEqual(result["local_preflight_result"], "READY")
        self.assertEqual(
            result["candidate"]["expected_signer_certificate_der_sha256"],
            SIGNER_SHA256,
        )

    def test_accepts_ready_observation_when_default_wsl_version_is_one(
        self,
    ) -> None:
        document = ready_document()
        document["docker"]["wsl_default_version"] = 1

        result = validate_windows_e4_preflight(document=document, schema=self.schema)

        self.assertEqual(result["local_preflight_result"], "READY")
        self.assertEqual(result["docker"]["wsl_default_version"], 1)
        self.assertEqual(result["e4_result"], "NOT_RUN")
        self.assertFalse(result["release_approved"])

    def test_accepts_blocked_observation(self) -> None:
        document = ready_document()
        document["local_preflight_result"] = "BLOCKED"
        document["docker"]["engine_available"] = False
        document["docker"]["server_os"] = None
        document["docker"]["server_architecture"] = None
        document["checks"] = _checks(blocked={"DOCKER_DESKTOP_LINUX_AMD64"})

        result = validate_windows_e4_preflight(document=document, schema=self.schema)

        self.assertEqual(result["local_preflight_result"], "BLOCKED")
        self.assertEqual(result["e4_result"], "NOT_RUN")
        self.assertFalse(result["release_approved"])

    def test_accepts_blocked_observation_when_backend_is_not_linux_amd64(
        self,
    ) -> None:
        document = ready_document()
        document["local_preflight_result"] = "BLOCKED"
        document["docker"]["server_os"] = "windows"
        document["checks"] = _checks(blocked={"DOCKER_DESKTOP_LINUX_AMD64"})

        result = validate_windows_e4_preflight(document=document, schema=self.schema)

        self.assertEqual(result["local_preflight_result"], "BLOCKED")
        self.assertEqual(result["e4_result"], "NOT_RUN")

    def test_rejects_tampered_signer_observation(self) -> None:
        document = ready_document()
        document["candidate"]["setup"]["signer_certificate_der_sha256"] = "e" * 64

        with self.assertRaisesRegex(ValueError, "signer_matches"):
            validate_windows_e4_preflight(document=document, schema=self.schema)

    def test_rejects_tampered_hash_observation(self) -> None:
        document = ready_document()
        document["candidate"]["launcher"]["sha256"] = "f" * 64

        with self.assertRaisesRegex(ValueError, "hash_matches"):
            validate_windows_e4_preflight(document=document, schema=self.schema)

    def test_rejects_tampered_check_result(self) -> None:
        document = ready_document()
        document["checks"] = _checks(blocked={"VIRTUALIZATION"})

        with self.assertRaisesRegex(ValueError, "VIRTUALIZATION"):
            validate_windows_e4_preflight(document=document, schema=self.schema)

    def test_rejects_release_candidate_for_a_different_commit(self) -> None:
        document = ready_document()
        document["release_candidate"] = "0.1.0-a1b2c3d4e5f6"

        with self.assertRaisesRegex(ValueError, "does not bind the commit prefix"):
            validate_windows_e4_preflight(document=document, schema=self.schema)

    def test_validator_keeps_candidate_binding_if_schema_is_accidentally_relaxed(
        self,
    ) -> None:
        document = ready_document()
        document["release_candidate"] = "unbound-candidate"
        relaxed_schema = copy.deepcopy(self.schema)
        relaxed_schema["properties"]["release_candidate"] = {"type": "string"}

        with self.assertRaisesRegex(ValueError, "candidate identity is malformed"):
            validate_windows_e4_preflight(document=document, schema=relaxed_schema)

    def test_rejects_e4_result_other_than_not_run(self) -> None:
        document = ready_document()
        document["e4_result"] = "PASSED"

        with self.assertRaisesRegex(ValueError, "e4_result"):
            validate_windows_e4_preflight(document=document, schema=self.schema)

    def test_validator_keeps_not_run_boundary_if_schema_is_accidentally_relaxed(
        self,
    ) -> None:
        document = ready_document()
        document["e4_result"] = "PASSED"
        relaxed_schema = copy.deepcopy(self.schema)
        relaxed_schema["properties"]["e4_result"] = {"type": "string"}

        with self.assertRaisesRegex(ValueError, "must remain NOT_RUN"):
            validate_windows_e4_preflight(document=document, schema=relaxed_schema)

    def test_validator_keeps_release_boundary_if_schema_is_accidentally_relaxed(
        self,
    ) -> None:
        document = ready_document()
        document["release_approved"] = True
        relaxed_schema = copy.deepcopy(self.schema)
        relaxed_schema["properties"]["release_approved"] = {"type": "boolean"}

        with self.assertRaisesRegex(ValueError, "must not approve a release"):
            validate_windows_e4_preflight(document=document, schema=relaxed_schema)

    def test_file_validator_accepts_utf8_json_object(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            input_path = Path(temporary_directory) / "preflight.json"
            input_path.write_text(
                json.dumps(ready_document(), ensure_ascii=False), encoding="utf-8"
            )

            result = validate_windows_e4_preflight_file(
                input_path=input_path, schema_path=SCHEMA_PATH
            )

        self.assertEqual(result["local_preflight_result"], "READY")

    def test_contract_and_validator_keep_the_not_run_boundary(self) -> None:
        properties = self.schema["properties"]
        self.assertEqual(properties["e4_result"], {"const": "NOT_RUN"})
        self.assertEqual(properties["release_approved"], {"const": False})
        self.assertEqual(
            properties["harness_version"], {"const": "windows-e4-preflight/v1"}
        )
        self.assertIn("commit_sha", properties["release_candidate"]["description"])
        self.assertFalse(self.schema["additionalProperties"])
        ready_docker = self.schema["allOf"][0]["then"]["properties"]["docker"][
            "properties"
        ]
        self.assertNotIn("wsl_default_version", ready_docker)
        self.assertEqual(ready_docker["wsl_status_available"], {"const": True})
        self.assertEqual(
            EXPECTED_CHECK_IDS,
            {
                "WIN11_X64_CLIENT",
                "VIRTUALIZATION",
                "WSL2_STATUS",
                "DOCKER_AMBIENT_CONTEXT",
                "DOCKER_DESKTOP_LINUX_AMD64",
                "DOCKER_COMPOSE_V2",
                "CANDIDATE_HASHES",
                "CANDIDATE_SIGNATURES",
                "PRODUCT_STATE_ABSENT",
            },
        )

    def test_powershell_source_only_observes_prerequisites(self) -> None:
        source = POWERSHELL_PATH.read_text(encoding="utf-8")
        executable_lines = "\n".join(
            line.split("#", 1)[0] for line in source.splitlines()
        ).lower()

        self.assertIn('e4_result = "not_run"', executable_lines)
        self.assertIn("release_approved = $false", executable_lines)
        self.assertNotRegex(
            executable_lines,
            re.compile(r"release_approved\s*=\s*\$true", re.IGNORECASE),
        )
        self.assertIn("[io.filemode]::createnew", executable_lines)
        self.assertIn('"version", "--format", "{{.server.os}}|{{.server.arch}}"', executable_lines)
        self.assertIn('"volume", "ls", "--quiet", "--filter",', executable_lines)
        self.assertIn('-id "wsl2_status"', executable_lines)
        self.assertIn("releasecandidate must bind the exact commitsha prefix", executable_lines)
        self.assertNotIn("wsl_default_version -eq 2", executable_lines)

        for forbidden in (
            "start-process",
            "invoke-expression",
            "start-job",
            "invoke-webrequest",
            "explorer.exe",
            "cmd.exe",
            "msedge.exe",
            "chrome.exe",
            "firefox.exe",
            "[diagnostics.process]::start",
            "setup.exe",
            "launcher.exe",
            "datax.py",
            "datax.exe",
            "java.exe",
            "enable-windowsoptionalfeature",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, executable_lines)

        self.assertNotRegex(
            executable_lines,
            re.compile(
                r"&\s+\$(?:setup|launcher|datax)(?:path)?(?:\.fullname)?\b",
                re.IGNORECASE,
            ),
        )
        self.assertNotRegex(
            executable_lines,
            re.compile(r"&\s+\$wslpath\.fullname\s+--install\b", re.IGNORECASE),
        )

        self.assertNotRegex(
            executable_lines,
            re.compile(
                r"&\s+\$composepath\s+(?!version\s+--short)(?:[^\r\n]*)",
                re.IGNORECASE,
            ),
        )
        self.assertNotRegex(
            executable_lines,
            re.compile(
                r"\b(?:docker|docker-compose)(?:\.exe)?\s+"
                r"(?:compose\s+)?(?:up|run|start|down|build|pull|exec|create)\b",
                re.IGNORECASE,
            ),
        )

    def test_windows_ci_parses_the_preflight_script(self) -> None:
        ci_workflow = CI_WORKFLOW_PATH.read_text(encoding="utf-8")
        self.assertIn("Windows launcher", ci_workflow)
        self.assertIn("Parse Windows release scripts", ci_workflow)
        for path in (
            "scripts/windows/build-installer.ps1",
            "scripts/windows/validate-release.ps1",
            "scripts/release/finalize_windows_publisher_binding.ps1",
            "scripts/release/verify_windows_publisher_binding.ps1",
            "scripts/acceptance/windows_e4_preflight.ps1",
        ):
            with self.subTest(path=path):
                self.assertIn(f'"{path}"', ci_workflow)


if __name__ == "__main__":
    unittest.main()
