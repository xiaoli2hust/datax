from __future__ import annotations

import unittest
from pathlib import Path

import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
RELEASE_WORKFLOW = REPOSITORY_ROOT / ".github/workflows/release.yml"
ATTEST_ACTION = "actions/attest@508db95dd578ae2727ebd6217d5ba78e4fbda05d"


class ReleaseWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.raw = RELEASE_WORKFLOW.read_text(encoding="utf-8")
        cls.workflow = yaml.load(cls.raw, Loader=yaml.BaseLoader)

    def test_hosted_attestor_has_the_fixed_trust_boundary(self) -> None:
        job = self.workflow["jobs"]["hosted-candidate-attestor"]
        self.assertEqual(job["runs-on"], "ubuntu-24.04")
        self.assertEqual(
            job["needs"],
            ["linux-images", "windows-signed-candidate"],
        )
        self.assertEqual(
            job["permissions"],
            {
                "contents": "read",
                "id-token": "write",
                "attestations": "write",
                "artifact-metadata": "write",
            },
        )
        actions = [step.get("uses") for step in job["steps"] if step.get("uses")]
        self.assertIn(ATTEST_ACTION, actions)
        self.assertNotIn("self-hosted", str(job["runs-on"]))

    def test_handoff_hash_precedes_root_and_attestation(self) -> None:
        job = self.workflow["jobs"]["hosted-candidate-attestor"]
        names = [step["name"] for step in job["steps"]]
        root_index = names.index(
            "Verify the handoff manifest and establish the canonical blocked root"
        )
        linux_evidence_index = names.index("Download independently built Linux evidence")
        handoff_index = names.index("Download the complete blocked Windows handoff candidate")
        attest_index = names.index("Attest the canonical blocked candidate root")
        policy_index = names.index(
            "Re-verify provenance and require the stable TCB blocker"
        )
        self.assertLess(linux_evidence_index, handoff_index)
        self.assertLess(handoff_index, root_index)
        self.assertLess(root_index, attest_index)
        self.assertLess(attest_index, policy_index)

        root_script = job["steps"][root_index]["run"]
        self.assertLess(
            root_script.index('--root "${TRUSTED_LINUX_EVIDENCE_DIRECTORY}"'),
            root_script.index('--root "${CANDIDATE_DIRECTORY}"'),
        )
        self.assertLess(
            root_script.index("hash_manifest.py"),
            root_script.index('unlink "${CANDIDATE_DIRECTORY}/SHA256SUMS"'),
        )
        self.assertLess(
            root_script.index('unlink "${CANDIDATE_DIRECTORY}/SHA256SUMS"'),
            root_script.index("candidate_root.py \\\n  generate"),
        )
        self.assertIn("candidate_root.py \\\n  validate", root_script)
        self.assertEqual(
            root_script.count("--trusted-linux-evidence-directory"),
            2,
        )
        self.assertIn("Candidate-bound Windows E4 result catalog is absent.", root_script)
        self.assertIn("Protected Windows E4 harness evidence is absent.", root_script)
        policy_script = job["steps"][policy_index]["run"]
        self.assertIn("--trusted-linux-evidence-directory", policy_script)

        linux_job = self.workflow["jobs"]["linux-images"]
        manifest_step = next(
            step
            for step in linux_job["steps"]
            if step["name"] == "Bind an explicit blocked acceptance manifest to this candidate"
        )
        manifest_script = manifest_step["run"]
        self.assertIn("windows_e4_scenarios.py", manifest_script)
        self.assertIn("windows-e4-scenario-profile.v1.json", manifest_script)
        self.assertIn("--require-authoritative", manifest_script)

    def test_candidate_assembly_requires_a_nonempty_regular_owner_license(self) -> None:
        job = self.workflow["jobs"]["linux-images"]
        names = [step["name"] for step in job["steps"]]
        identity_index = names.index("Validate candidate identity")
        license_index = names.index(
            "Require an owner-selected root license before candidate assembly"
        )
        manifest_index = names.index(
            "Bind an explicit blocked acceptance manifest to this candidate"
        )
        self.assertLess(identity_index, license_index)
        self.assertLess(license_index, manifest_index)

        script = job["steps"][license_index]["run"]
        self.assertIn("set -euo pipefail", script)
        self.assertIn("[[ ! -f LICENSE || -L LICENSE || ! -s LICENSE ]]", script)
        self.assertIn('Path("LICENSE").read_text(encoding="utf-8")', script)
        self.assertIn('"\\x00" in contents or not contents.strip()', script)
        self.assertIn("repository owner", script)

    def test_all_candidate_artifacts_and_the_policy_remain_explicitly_blocked(
        self,
    ) -> None:
        windows_job = self.workflow["jobs"]["windows-signed-candidate"]
        windows_upload = windows_job["steps"][-1]
        self.assertTrue(windows_upload["with"]["name"].startswith("blocked-"))

        hosted_job = self.workflow["jobs"]["hosted-candidate-attestor"]
        upload_names = [
            step["with"]["name"]
            for step in hosted_job["steps"]
            if step.get("uses", "").startswith("actions/upload-artifact@")
        ]
        self.assertEqual(len(upload_names), 2)
        self.assertTrue(all(name.startswith("blocked-") for name in upload_names))
        hosted_text = str(hosted_job)
        self.assertIn("TRUSTED_ATTESTATION_VERIFIER_TCB_NOT_IMPLEMENTED", hosted_text)
        self.assertNotIn("--require-pass", hosted_text)
        self.assertNotIn("release_approved=true", hosted_text)

    def test_environment_preflight_precedes_any_signing_job_environment_reference(self) -> None:
        preflight = self.workflow["jobs"]["signing-environment-preflight"]
        self.assertEqual(preflight["runs-on"], "ubuntu-24.04")
        self.assertNotIn("needs", preflight)
        self.assertEqual(
            preflight["permissions"],
            {"actions": "read", "contents": "read"},
        )
        self.assertNotIn("environment", preflight)
        self.assertNotIn("secrets.", str(preflight))
        self.assertNotIn("vars.", str(preflight))
        self.assertEqual(
            set(preflight["outputs"]),
            {"ready", "environment_id", "protection_sha256"},
        )
        preflight_script = next(
            step
            for step in preflight["steps"]
            if step["name"]
            == "Read and strictly validate the pre-existing signing environment"
        )["run"]
        self.assertIn("/environments/${environment_name}", preflight_script)
        self.assertIn("verify_signing_environment.py", preflight_script)
        self.assertIn("environment_id", preflight_script)
        self.assertIn("protection_sha256", preflight_script)
        self.assertIn("deployment-branch-policies?per_page=100", preflight_script)
        self.assertIn("--selector-mode", preflight_script)
        self.assertIn("--deployment-branch-policies-json", preflight_script)
        self.assertIn("branch_policies_path", preflight_script)
        self.assertIn("branch_policies_uri", preflight_script)
        self.assertNotIn("reviewers", preflight_script)

        linux_job = self.workflow["jobs"]["linux-images"]
        self.assertEqual(linux_job["needs"], "signing-environment-preflight")
        self.assertEqual(
            linux_job["if"],
            "needs.signing-environment-preflight.outputs.ready == 'true'",
        )

        job = self.workflow["jobs"]["windows-signed-candidate"]
        self.assertEqual(
            job["needs"],
            ["linux-images", "signing-environment-preflight"],
        )
        self.assertEqual(
            job["if"],
            "needs.signing-environment-preflight.outputs.ready == 'true'",
        )
        self.assertEqual(job["environment"], "windows-candidate-signing")
        self.assertEqual(job["permissions"], {"actions": "read", "contents": "read"})
        names = [step["name"] for step in job["steps"]]
        verifier_index = names.index(
            "Revalidate the pre-existing approval-gated signing environment before secrets"
        )
        certificate_index = names.index("Require and import the protected signing certificate")
        self.assertLess(verifier_index, certificate_index)
        script = job["steps"][verifier_index]["run"]
        self.assertIn("/environments/$environmentName", script)
        self.assertIn("verify_signing_environment.py", script)
        self.assertIn("--expected-environment-id", script)
        self.assertIn("--expected-protection-sha256", script)
        self.assertIn("EXPECTED_ENVIRONMENT_ID", script)
        self.assertIn("EXPECTED_PROTECTION_SHA256", script)
        self.assertIn("finally", script)
        self.assertIn("Remove-Item -LiteralPath $environmentPath -Force", script)
        self.assertIn("Remove-Item -LiteralPath $branchPoliciesPath -Force", script)
        self.assertIn("deployment-branch-policies?per_page=100", script)
        self.assertIn("--selector-mode", script)
        self.assertIn("--deployment-branch-policies-json", script)
        self.assertIn("$branchPoliciesUri", script)
        self.assertNotIn("Write-Output $response.Content", script)
        self.assertIn("prevent", (REPOSITORY_ROOT / "scripts/release/verify_signing_environment.py").read_text(encoding="utf-8"))

    def test_windows_signing_uses_the_dedicated_runner_group(self) -> None:
        job = self.workflow["jobs"]["windows-signed-candidate"]
        self.assertEqual(
            job["runs-on"],
            {
                "group": "datax-release-signing",
                "labels": [
                    "self-hosted",
                    "windows",
                    "x64",
                    "datax-release-windows11",
                ],
            },
        )

    def test_windows_signing_checks_a_clean_checkout_and_tools_before_pfx(self) -> None:
        job = self.workflow["jobs"]["windows-signed-candidate"]
        names = [step["name"] for step in job["steps"]]
        preflight_index = names.index(
            "Require a clean checkout and configured local signing tools"
        )
        certificate_index = names.index(
            "Require and import the protected signing certificate"
        )
        self.assertLess(preflight_index, certificate_index)

        preflight = job["steps"][preflight_index]
        self.assertEqual(
            preflight["env"],
            {
                "CARGO_PATH": "${{ vars.CARGO_PATH }}",
                "MAKENSIS_PATH": "${{ vars.MAKENSIS_PATH }}",
                "RUSTC_PATH": "${{ vars.RUSTC_PATH }}",
                "SIGNTOOL_PATH": "${{ vars.SIGNTOOL_PATH }}",
            },
        )
        script = preflight["run"]
        self.assertIn("git diff --quiet HEAD --", script)
        self.assertIn(
            "git status --porcelain=v1 --untracked-files=all",
            script,
        )
        self.assertIn("Assert-ConfiguredLocalExecutable", script)
        self.assertIn("Get-CimInstance", script)
        self.assertIn("Win32_LogicalDisk", script)
        self.assertIn("ReparsePoint", script)
        self.assertIn("Assert-NoCargoCompilerOverrides", script)
        for tool, variable in (
            ("cargo.exe", "CARGO_PATH"),
            ("makensis.exe", "MAKENSIS_PATH"),
            ("rustc.exe", "RUSTC_PATH"),
            ("signtool.exe", "SIGNTOOL_PATH"),
        ):
            self.assertIn(f'"{tool}" = $env:{variable}', script)
        for variable in (
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_BUILD_RUSTFLAGS",
            "CARGO_TARGET_DIR",
            "CARGO_HOME",
        ):
            self.assertIn(f'"{variable}"', script)

    def test_windows_release_scripts_require_configured_non_path_tools(self) -> None:
        expected = {
            "scripts/windows/build-installer.ps1": (
                "CargoPath",
                "RustcPath",
                "MakensisPath",
                "SigntoolPath",
                "AllowedSignerFile",
            ),
            "scripts/release/finalize_windows_publisher_binding.ps1": (
                "CargoPath",
                "RustcPath",
                "MakensisPath",
                "SigntoolPath",
            ),
            "scripts/windows/validate-release.ps1": (
                "CargoPath",
                "RustcPath",
                "SigntoolPath",
            ),
        }
        for relative_path, parameters in expected.items():
            source = (REPOSITORY_ROOT / relative_path).read_text(encoding="utf-8")
            self.assertNotIn("Get-Command", source)
            self.assertIn("function Resolve-RequiredExecutable", source)
            self.assertIn("Get-CimInstance", source)
            self.assertIn("Win32_LogicalDisk", source)
            self.assertIn("ReparsePoint", source)
            self.assertIn("function Assert-NoCargoCompilerOverrides", source)
            self.assertIn("function Invoke-ConfiguredCargo", source)
            self.assertIn('"RUSTC"', source)
            self.assertNotIn("& $cargo", source)
            for variable in (
                "RUSTC_WRAPPER",
                "RUSTFLAGS",
                "CARGO_ENCODED_RUSTFLAGS",
                "CARGO_BUILD_RUSTFLAGS",
                "CARGO_TARGET_DIR",
                "CARGO_HOME",
            ):
                self.assertIn(f'"{variable}"', source)
            for parameter in parameters:
                self.assertIn(
                    f"[Parameter(Mandatory = $true)]\n    [string]${parameter}",
                    source,
                )

    def test_workflow_passes_the_mandatory_tool_paths_to_each_release_script(self) -> None:
        job = self.workflow["jobs"]["windows-signed-candidate"]
        names = [step["name"] for step in job["steps"]]
        self.assertLess(
            names.index("Recheck tracked sources before candidate assembly"),
            names.index("Assemble and verify the signed candidate evidence"),
        )
        self.assertLess(
            names.index("Assemble and verify the signed candidate evidence"),
            names.index("Recheck tracked sources after all toolchain execution"),
        )
        self.assertLess(
            names.index("Recheck tracked sources after all toolchain execution"),
            names.index("Remove imported signing certificates"),
        )
        self.assertLess(
            names.index("Recheck tracked sources after all toolchain execution"),
            names.index("Upload signed candidate artifact and evidence"),
        )
        final_recheck = job["steps"][
            names.index("Recheck tracked sources after all toolchain execution")
        ]["run"]
        self.assertIn("git diff --quiet HEAD --", final_recheck)

        build = next(
            step
            for step in job["steps"]
            if step["name"] == "Build and sign Launcher and Setup"
        )["run"]
        for parameter, variable in (
            ("CargoPath", "CARGO_PATH"),
            ("RustcPath", "RUSTC_PATH"),
            ("MakensisPath", "MAKENSIS_PATH"),
            ("SigntoolPath", "SIGNTOOL_PATH"),
        ):
            self.assertEqual(build.count(f"{parameter} = $env:{variable}"), 2)
        self.assertIn("AllowedSignerFile = $env:SIGNER_ALLOWLIST_PATH", build)

        candidate = next(
            step
            for step in job["steps"]
            if step["name"] == "Assemble and verify the signed candidate evidence"
        )["run"]
        for parameter, variable in (
            ("CargoPath", "CARGO_PATH"),
            ("RustcPath", "RUSTC_PATH"),
            ("SigntoolPath", "SIGNTOOL_PATH"),
        ):
            self.assertIn(f"{parameter} = $env:{variable}", candidate)

    def test_builder_emits_the_same_release_manifest_contract_as_the_launcher(self) -> None:
        builder = (
            REPOSITORY_ROOT / "scripts/windows/build-installer.ps1"
        ).read_text(encoding="utf-8")
        launcher = (
            REPOSITORY_ROOT / "desktop/windows/src/lib.rs"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "[Parameter(Mandatory = $true)]\n    [string]$AllowedSignerFile",
            builder,
        )
        self.assertIn("function Read-CanonicalSignerAllowlist", builder)
        self.assertIn("$values.Count -lt 1 -or $values.Count -gt 8", builder)
        self.assertIn("'^[0-9a-f]{64}$'", builder)
        self.assertIn("strictly ordinal-sorted and unique", builder)
        self.assertIn("Publisher allowlist must use the exact canonical JSON form.", builder)
        self.assertIn("$allowedSigners = Read-CanonicalSignerAllowlist", builder)
        self.assertIn("$expectedSignerSha256 = Get-CertificateSha256", builder)
        self.assertIn(
            "The selected signing certificate is absent from the protected SHA-256 allowlist.",
            builder,
        )
        self.assertIn('schema_version = "1.1"', builder)
        self.assertIn(
            "allowed_authenticode_signer_certificate_sha256 = @($allowedSigners)",
            builder,
        )
        self.assertNotIn('schema_version = "1.0"\n    product_version = $ProductVersion', builder)
        self.assertIn('manifest.schema_version != "1.1"', launcher)
        self.assertIn("allowed_authenticode_signer_certificate_sha256", launcher)

    def test_verifier_download_is_bound_to_the_locked_installer(self) -> None:
        job = self.workflow["jobs"]["hosted-candidate-attestor"]
        step = next(
            item
            for item in job["steps"]
            if item["name"] == "Install the hash-locked GitHub CLI verifier"
        )
        script = step["run"]
        self.assertIn("trusted_gh_cli.py archive-url", script)
        self.assertIn("trusted_gh_cli.py \\\n  install", script)
        self.assertIn("trusted_gh_cli.py \\\n  verify", script)
        self.assertIn("--proto '=https'", script)
        self.assertIn("--proto-redir '=https'", script)
        self.assertIn("--tlsv1.2", script)


if __name__ == "__main__":
    unittest.main()
