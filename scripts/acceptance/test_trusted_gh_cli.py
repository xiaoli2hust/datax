from __future__ import annotations

import hashlib
import io
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.acceptance import trusted_gh_cli


class TrustedGitHubCliTests(unittest.TestCase):
    def test_authoritative_lock_is_exact(self) -> None:
        self.assertEqual(trusted_gh_cli.TRUSTED_GH_VERSION, "2.97.0")
        self.assertEqual(
            trusted_gh_cli.TRUSTED_GH_ARCHIVE_URL,
            "https://github.com/cli/cli/releases/download/v2.97.0/"
            "gh_2.97.0_linux_amd64.tar.gz",
        )
        self.assertEqual(
            trusted_gh_cli.TRUSTED_GH_ARCHIVE_SHA256,
            "a2c9b8497e1f85b1ad0dfcb78b5a622e098801b8e461e459e88e1ee12f018112",
        )
        self.assertEqual(
            trusted_gh_cli.TRUSTED_GH_EXECUTABLE_SHA256,
            "141507c337e8b202ad398550c3b73d72f5af92e86f71665214538a81efd4c409",
        )

    def test_install_and_verify_exact_locked_executable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            archive = root / "gh.tar.gz"
            executable_bytes = b"fixture trusted gh executable\n"
            member_name = "fixture/bin/gh"
            self._write_regular_archive(
                archive,
                member_name=member_name,
                content=executable_bytes,
            )
            output = root / "trusted-gh"
            archive_sha256 = hashlib.sha256(archive.read_bytes()).hexdigest()
            executable_sha256 = hashlib.sha256(executable_bytes).hexdigest()

            with self._fixture_lock(
                archive_sha256=archive_sha256,
                executable_sha256=executable_sha256,
                member_name=member_name,
            ):
                installed = trusted_gh_cli.install_trusted_gh(
                    archive_path=archive,
                    output_path=output,
                )

                calls: list[list[str]] = []

                def runner(
                    command: list[str], **_kwargs: object
                ) -> subprocess.CompletedProcess[str]:
                    calls.append(command)
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        stdout=(
                            "gh version 2.97.0 (fixture)\n"
                            "https://github.com/cli/cli/releases/tag/v2.97.0\n"
                        ),
                        stderr="",
                    )

                with (
                    mock.patch.object(trusted_gh_cli.sys, "platform", "linux"),
                    mock.patch.object(
                        trusted_gh_cli.platform, "machine", return_value="x86_64"
                    ),
                ):
                    verified = trusted_gh_cli.verify_trusted_gh(
                        executable_path=output,
                        runner=runner,
                    )

            self.assertEqual(installed["code"], "TRUSTED_GH_CLI_INSTALLED")
            self.assertEqual(verified["code"], "TRUSTED_GH_CLI_VALID")
            self.assertEqual(output.read_bytes(), executable_bytes)
            self.assertEqual(calls, [[str(output), "version"]])

    def test_archive_hash_and_link_member_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            archive = root / "gh.tar.gz"
            self._write_regular_archive(
                archive,
                member_name="fixture/bin/gh",
                content=b"fixture\n",
            )
            with (
                self._fixture_lock(
                    archive_sha256="0" * 64,
                    executable_sha256="1" * 64,
                    member_name="fixture/bin/gh",
                ),
                self.assertRaisesRegex(ValueError, "archive SHA-256"),
            ):
                trusted_gh_cli.install_trusted_gh(
                    archive_path=archive,
                    output_path=root / "bad-hash-gh",
                )

            link_archive = root / "link.tar.gz"
            with tarfile.open(link_archive, mode="w:gz") as bundle:
                member = tarfile.TarInfo("fixture/bin/gh")
                member.type = tarfile.SYMTYPE
                member.linkname = "../../untrusted"
                bundle.addfile(member)
            with (
                self._fixture_lock(
                    archive_sha256=hashlib.sha256(
                        link_archive.read_bytes()
                    ).hexdigest(),
                    executable_sha256="1" * 64,
                    member_name="fixture/bin/gh",
                ),
                self.assertRaisesRegex(ValueError, "not a safe file"),
            ):
                trusted_gh_cli.install_trusted_gh(
                    archive_path=link_archive,
                    output_path=root / "link-gh",
                )

    def test_binary_hash_version_and_symlink_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            executable = root / "gh"
            executable.write_bytes(b"fixture\n")
            executable.chmod(0o755)
            with (
                self._fixture_lock(
                    archive_sha256="0" * 64,
                    executable_sha256="1" * 64,
                    member_name="fixture/bin/gh",
                ),
                mock.patch.object(trusted_gh_cli.sys, "platform", "linux"),
                mock.patch.object(
                    trusted_gh_cli.platform, "machine", return_value="x86_64"
                ),
                self.assertRaisesRegex(ValueError, "executable SHA-256"),
            ):
                trusted_gh_cli.verify_trusted_gh(executable_path=executable)

            executable_sha256 = hashlib.sha256(executable.read_bytes()).hexdigest()
            with self._fixture_lock(
                archive_sha256="0" * 64,
                executable_sha256=executable_sha256,
                member_name="fixture/bin/gh",
            ):

                def wrong_version(
                    command: list[str], **_kwargs: object
                ) -> subprocess.CompletedProcess[str]:
                    return subprocess.CompletedProcess(
                        command,
                        0,
                        stdout="gh version 9.9.9 (fixture)\nhttps://example.invalid\n",
                        stderr="",
                    )

                with (
                    mock.patch.object(trusted_gh_cli.sys, "platform", "linux"),
                    mock.patch.object(
                        trusted_gh_cli.platform, "machine", return_value="x86_64"
                    ),
                    self.assertRaisesRegex(ValueError, "version output"),
                ):
                    trusted_gh_cli.verify_trusted_gh(
                        executable_path=executable,
                        runner=wrong_version,
                    )

            symlink = root / "gh-link"
            symlink.symlink_to(executable)
            with self.assertRaisesRegex(ValueError, "symlink"):
                trusted_gh_cli.verify_trusted_gh(executable_path=symlink)

    @staticmethod
    def _write_regular_archive(path: Path, *, member_name: str, content: bytes) -> None:
        with tarfile.open(path, mode="w:gz") as bundle:
            member = tarfile.TarInfo(member_name)
            member.mode = 0o755
            member.size = len(content)
            bundle.addfile(member, io.BytesIO(content))

    @staticmethod
    def _fixture_lock(
        *, archive_sha256: str, executable_sha256: str, member_name: str
    ) -> mock._patch_dict:
        return mock.patch.multiple(
            trusted_gh_cli,
            TRUSTED_GH_ARCHIVE_SHA256=archive_sha256,
            TRUSTED_GH_EXECUTABLE_SHA256=executable_sha256,
            TRUSTED_GH_ARCHIVE_MEMBER=member_name,
        )


if __name__ == "__main__":
    unittest.main()
