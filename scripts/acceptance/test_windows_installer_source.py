from __future__ import annotations

import unittest
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
INSTALLER_SOURCE = REPOSITORY_ROOT / "installer/windows/DataXEnterpriseStudio.nsi"


def function_body(source: str, name: str) -> str:
    marker = f"Function {name}\n"
    _, remainder = source.split(marker, 1)
    return remainder.split("FunctionEnd", 1)[0]


def section_body(source: str, name: str) -> str:
    marker = f'Section "{name}"'
    _, remainder = source.split(marker, 1)
    return remainder.split("SectionEnd", 1)[0]


class WindowsInstallerSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = INSTALLER_SOURCE.read_text(encoding="utf-8")

    def test_fixed_per_user_root_rejects_directory_and_crc_bypasses(self) -> None:
        self.assertIn(
            '!define INSTALL_DIRECTORY "$LOCALAPPDATA\\Programs\\DataXEnterpriseStudio"',
            self.source,
        )
        self.assertIn('InstallDir "${INSTALL_DIRECTORY}"', self.source)
        self.assertIn("CRCCheck force", self.source)

        on_init = function_body(self.source, ".onInit")
        self.assertIn("SetShellVarContext current", on_init)
        comparison = (
            'StrCmp $INSTDIR "${INSTALL_DIRECTORY}" '
            "installer_directory_verified installer_directory_rejected"
        )
        self.assertIn(comparison, on_init)
        self.assertIn("installer_directory_rejected:", on_init)
        self.assertIn("不支持 /D 覆盖", on_init)
        self.assertLess(on_init.index(comparison), on_init.index("InitPluginsDir"))

    def test_silent_install_and_uninstall_fail_closed_with_nonzero_exit_codes(self) -> None:
        install_init = function_body(self.source, ".onInit")
        uninstall_init = function_body(self.source, "un.onInit")
        for body, rejected_label, interactive_label in [
            (
                install_init,
                "installer_silent_rejected",
                "installer_interactive",
            ),
            (
                uninstall_init,
                "uninstaller_silent_rejected",
                "uninstaller_interactive",
            ),
        ]:
            branch = f"IfSilent {rejected_label} {interactive_label}"
            rejected = f"{rejected_label}:"
            interactive = f"{interactive_label}:"
            self.assertIn(branch, body)
            self.assertIn(rejected, body)
            self.assertIn(interactive, body)
            self.assertLess(body.index(branch), body.index(rejected))
            self.assertLess(body.index(rejected), body.index("SetErrorLevel 2"))
            self.assertLess(body.index("SetErrorLevel 2"), body.index("Abort"))
            self.assertLess(body.index("Abort"), body.index(interactive))

    def test_candidate_release_verification_precedes_same_version_stop_and_repair(self) -> None:
        section = section_body(self.source, "DataX Enterprise Studio")
        verification = 'verify-release --installer "$EXEPATH"'
        stop = "Call StopExistingSameVersion"
        normalize = "Call NormalizeExistingResourceAttributes"
        self.assertIn("SetOverwrite on", section)
        self.assertIn("AllowSkipFiles off", section)
        self.assertIn(verification, section)
        self.assertIn(stop, section)
        self.assertIn(normalize, section)
        self.assertLess(section.index(verification), section.index(stop))
        self.assertLess(section.index(stop), section.index(normalize))

    def test_same_semver_repair_requires_the_same_persisted_release_candidate(self) -> None:
        self.assertIn('!ifndef RELEASE_CANDIDATE', self.source)
        self.assertIn('!error "RELEASE_CANDIDATE is required"', self.source)
        self.assertIn(
            'VIAddVersionKey /LANG=2052 "ReleaseCandidate" "${RELEASE_CANDIDATE}"',
            self.source,
        )

        on_init = function_body(self.source, ".onInit")
        version_compare = '${VersionCompare} $4 "${PRODUCT_VERSION}" $5'
        candidate_read = 'ReadRegStr $6 HKCU "${PRODUCT_KEY}" "ReleaseCandidate"'
        mismatch = '${If} $6 != "${RELEASE_CANDIDATE}"'
        self.assertIn(version_compare, on_init)
        self.assertIn(candidate_read, on_init)
        self.assertIn(mismatch, on_init)
        self.assertIn("同版本但不同发布候选", on_init)
        self.assertLess(on_init.index(version_compare), on_init.index(candidate_read))

        section = section_body(self.source, "DataX Enterprise Studio")
        for product_key in ("${PRODUCT_KEY}", "${UNINSTALL_KEY}"):
            self.assertIn(
                f'WriteRegStr HKCU "{product_key}" "ReleaseCandidate" "${{RELEASE_CANDIDATE}}"',
                section,
            )

    def test_repair_and_uninstall_bind_deletion_to_the_fixed_registry_root(self) -> None:
        normalize = function_body(self.source, "NormalizeExistingResourceAttributes")
        for resource in [
            "compose.yaml",
            "images.release.env",
            "secure-acl.ps1",
            "release-manifest.json",
        ]:
            self.assertIn(
                f'SetFileAttributes "$INSTDIR\\resources\\{resource}" NORMAL',
                normalize,
            )
        self.assertIn("无法解除现有发布资源的只读属性", normalize)

        same_version_stop = function_body(self.source, "StopExistingSameVersion")
        self.assertIn('${If} $1 != "${INSTALL_DIRECTORY}"', same_version_stop)

        uninstaller = function_body(self.source, "un.onInit")
        self.assertIn(
            'ReadRegStr $0 HKCU "${PRODUCT_KEY}" "InstallDir"',
            uninstaller,
        )
        self.assertIn('${If} $0 != "${INSTALL_DIRECTORY}"', uninstaller)
        self.assertIn('StrCpy $INSTDIR "${INSTALL_DIRECTORY}"', uninstaller)
        self.assertLess(
            uninstaller.index('StrCpy $INSTDIR "${INSTALL_DIRECTORY}"'),
            uninstaller.index('ExecWait \'"$INSTDIR\\launcher.exe" stop\' $0'),
        )

    def test_same_version_repair_stops_with_the_verified_candidate_launcher(self) -> None:
        same_version_stop = function_body(self.source, "StopExistingSameVersion")
        candidate_stop = (
            'ExecWait \'"$PLUGINSDIR\\release-check\\launcher.exe" stop\' $2'
        )
        self.assertIn(candidate_stop, same_version_stop)
        self.assertNotIn('$1\\launcher.exe', same_version_stop)
        self.assertNotIn("existing_launcher_missing:", self.source)
        self.assertLess(
            same_version_stop.index("Call AssertInstallationPathsNoReparse"),
            same_version_stop.index(candidate_stop),
        )

    def test_reparse_points_fail_closed_at_install_repair_and_uninstall_boundaries(self) -> None:
        self.assertIn("!define DES_FILE_ATTRIBUTE_REPARSE_POINT 0x0400", self.source)
        self.assertIn("!define DES_ERROR_FILE_NOT_FOUND 2", self.source)
        self.assertIn("!define DES_ERROR_PATH_NOT_FOUND 3", self.source)

        attribute_guard = function_body(self.source, "AssertPathNotReparseOrMissing")
        self.assertIn(
            "System::Call 'kernel32::GetFileAttributesW(w r0)i .r1?e'",
            attribute_guard,
        )
        self.assertIn(
            "IntOp $2 $1 & ${DES_FILE_ATTRIBUTE_REPARSE_POINT}",
            attribute_guard,
        )
        self.assertIn("junction/symlink", attribute_guard)

        tree_guard = function_body(self.source, "AssertInstallationPathsNoReparse")
        for guarded_path in [
            "$LOCALAPPDATA",
            "$LOCALAPPDATA\\Programs",
            "$INSTDIR",
            "$INSTDIR\\resources",
        ]:
            self.assertIn(f'Push "{guarded_path}"', tree_guard)

        leaves_guard = function_body(self.source, "AssertInstalledLeavesNoReparse")
        for guarded_leaf in [
            "launcher.exe",
            "compose.yaml",
            "images.release.env",
            "secure-acl.ps1",
            "release-manifest.json",
            "Uninstall.exe",
        ]:
            self.assertIn(guarded_leaf, leaves_guard)

        on_init = function_body(self.source, ".onInit")
        self.assertLess(
            on_init.index("Call AssertInstallationPathsNoReparse"),
            on_init.index("InitPluginsDir"),
        )

        repair = function_body(self.source, "NormalizeExistingResourceAttributes")
        self.assertLess(
            repair.index("Call AssertInstallationPathsNoReparse"),
            repair.index("SetFileAttributes"),
        )

        section = section_body(self.source, "DataX Enterprise Studio")
        self.assertGreaterEqual(section.count("Call AssertInstallationPathsNoReparse"), 6)
        self.assertGreaterEqual(section.count("Call AssertInstalledLeavesNoReparse"), 6)
        self.assertLess(
            section.index("Call AssertInstallationPathsNoReparse"),
            section.index('SetOutPath "$INSTDIR"'),
        )

        uninstaller = function_body(self.source, "un.onInit")
        self.assertLess(
            uninstaller.index("Call un.AssertInstallationPathsNoReparse"),
            uninstaller.index('ExecWait \'"$INSTDIR\\launcher.exe" stop\' $0'),
        )
        uninstall_section = section_body(self.source, "Uninstall")
        self.assertLess(
            uninstall_section.index("Call un.AssertInstallationPathsNoReparse"),
            uninstall_section.index('Delete "$INSTDIR\\resources\\compose.yaml"'),
        )

        uninstall_attribute_guard = function_body(
            self.source, "un.AssertPathNotReparseOrMissing"
        )
        self.assertIn(
            "System::Call 'kernel32::GetFileAttributesW(w r0)i .r1?e'",
            uninstall_attribute_guard,
        )
        self.assertIn(
            "IntOp $2 $1 & ${DES_FILE_ATTRIBUTE_REPARSE_POINT}",
            uninstall_attribute_guard,
        )

        uninstall_tree_guard = function_body(
            self.source, "un.AssertInstallationPathsNoReparse"
        )
        self.assertIn(
            "Call un.AssertPathNotReparseOrMissing", uninstall_tree_guard
        )
        uninstall_leaves_guard = function_body(
            self.source, "un.AssertInstalledLeavesNoReparse"
        )
        self.assertIn(
            "Call un.AssertPathNotReparseOrMissing", uninstall_leaves_guard
        )
        self.assertNotIn(
            "Call AssertInstallationPathsNoReparse", uninstaller
        )
        self.assertNotIn(
            "Call AssertInstallationPathsNoReparse", uninstall_section
        )


if __name__ == "__main__":
    unittest.main()
