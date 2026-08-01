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


if __name__ == "__main__":
    unittest.main()
