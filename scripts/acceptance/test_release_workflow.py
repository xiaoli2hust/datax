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
        attest_index = names.index("Attest the canonical blocked candidate root")
        policy_index = names.index(
            "Re-verify provenance and require the stable TCB blocker"
        )
        self.assertLess(root_index, attest_index)
        self.assertLess(attest_index, policy_index)

        root_script = job["steps"][root_index]["run"]
        self.assertLess(
            root_script.index("hash_manifest.py"),
            root_script.index('unlink "${CANDIDATE_DIRECTORY}/SHA256SUMS"'),
        )
        self.assertLess(
            root_script.index('unlink "${CANDIDATE_DIRECTORY}/SHA256SUMS"'),
            root_script.index("candidate_root.py \\\n  generate"),
        )
        self.assertIn("candidate_root.py \\\n  validate", root_script)
        self.assertIn("Protected Windows E4 harness evidence is absent.", root_script)

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
