Unicode true
RequestExecutionLevel user
SetCompressor /SOLID lzma
ManifestDPIAware true

!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "x64.nsh"
!include "WordFunc.nsh"
!insertmacro VersionCompare

!ifndef PRODUCT_VERSION
  !error "PRODUCT_VERSION is required"
!endif
!ifndef FILE_VERSION
  !error "FILE_VERSION is required"
!endif
!ifndef LAUNCHER_EXE
  !error "LAUNCHER_EXE is required"
!endif
!ifndef COMPOSE_FILE
  !error "COMPOSE_FILE is required"
!endif
!ifndef RELEASE_MANIFEST
  !error "RELEASE_MANIFEST is required"
!endif
!ifndef IMAGE_ENV_FILE
  !error "IMAGE_ENV_FILE is required"
!endif
!ifndef ACL_SCRIPT
  !error "ACL_SCRIPT is required"
!endif
!ifndef OUTPUT_FILE
  !define OUTPUT_FILE "DataX-Enterprise-Studio-Setup-${PRODUCT_VERSION}-x64.exe"
!endif

!define PRODUCT_NAME "DataX Enterprise Studio"
!define PRODUCT_KEY "Software\DataXEnterpriseStudio"
!define UNINSTALL_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\DataXEnterpriseStudio"
!define START_MENU_DIR "DataX Enterprise Studio"
!define INSTALL_DIRECTORY "$LOCALAPPDATA\Programs\DataXEnterpriseStudio"
!define DES_FILE_ATTRIBUTE_REPARSE_POINT 0x0400
!define DES_INVALID_FILE_ATTRIBUTES -1
!define DES_ERROR_FILE_NOT_FOUND 2
!define DES_ERROR_PATH_NOT_FOUND 3

Name "${PRODUCT_NAME}"
Caption "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "${OUTPUT_FILE}"
InstallDir "${INSTALL_DIRECTORY}"
; Do not permit the default /NCRC switch to bypass the installer's own
; corruption check. Authenticode remains the release trust control.
CRCCheck force
BrandingText "${PRODUCT_NAME}"

VIProductVersion "${FILE_VERSION}"
VIAddVersionKey /LANG=2052 "ProductName" "${PRODUCT_NAME}"
VIAddVersionKey /LANG=2052 "FileDescription" "${PRODUCT_NAME} 每用户安装程序"
VIAddVersionKey /LANG=2052 "ProductVersion" "${PRODUCT_VERSION}"
VIAddVersionKey /LANG=2052 "FileVersion" "${PRODUCT_VERSION}"
VIAddVersionKey /LANG=2052 "LegalCopyright" "Copyright (c) DataX Enterprise Studio contributors"

!define MUI_ABORTWARNING
!define MUI_ICON "${NSISDIR}\Contrib\Graphics\Icons\modern-install.ico"
!define MUI_UNICON "${NSISDIR}\Contrib\Graphics\Icons\modern-uninstall.ico"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "SimpChinese"

Function .onInit
  ; V1 needs explicit human confirmation for installation. IfSilent covers the
  ; NSIS silent state itself (including /S), not a brittle command-line parse.
  IfSilent installer_silent_rejected installer_interactive

installer_silent_rejected:
  SetErrorLevel 2
  Abort

installer_interactive:
  SetRegView 64
  SetShellVarContext current
  ; NSIS accepts /D=<path> by default. V1 has one fixed per-user installation
  ; root, so reject any command-line override before extracting a single file.
  StrCmp $INSTDIR "${INSTALL_DIRECTORY}" installer_directory_verified installer_directory_rejected

installer_directory_rejected:
  MessageBox MB_OK|MB_ICONSTOP "安装目录必须是当前用户的 %LOCALAPPDATA%\Programs\DataXEnterpriseStudio；不支持 /D 覆盖。安装已终止。"
  Abort

installer_directory_verified:
  ; Do not allow a pre-existing install tree to redirect file writes, repair,
  ; launcher execution, or uninstall deletes through a junction/symlink.
  Call AssertInstallationPathsNoReparse
  Call AssertInstalledLeavesNoReparse
  ; The release verifier is extracted to $PLUGINSDIR below. Do not rely on an
  ; incidental plug-in invocation to create that directory first.
  InitPluginsDir
  ${IfNot} ${RunningX64}
    MessageBox MB_OK|MB_ICONSTOP "仅支持 Windows 11 x64。安装已终止。"
    Abort
  ${EndIf}

  System::Call 'kernel32::GetCurrentProcess()p .r0'
  System::Call 'kernel32::IsWow64Process2(p r0, *i .r1, *i .r2)i .r3'
  ${If} $3 == 0
    MessageBox MB_OK|MB_ICONSTOP "无法核验原生 CPU 架构。安装已终止。"
    Abort
  ${EndIf}
  IntCmp $2 0x8664 native_amd64 native_arch_rejected native_arch_rejected

native_arch_rejected:
  MessageBox MB_OK|MB_ICONSTOP "仅支持原生 AMD64 Windows；Windows on Arm 仿真不受支持。安装已终止。"
  Abort

native_amd64:
  ReadRegStr $0 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion" "CurrentBuildNumber"
  ${If} $0 == ""
    MessageBox MB_OK|MB_ICONSTOP "无法核验 Windows 版本。安装已终止。"
    Abort
  ${EndIf}
  IntCmp $0 22000 windows_supported windows_unsupported windows_supported

windows_unsupported:
  MessageBox MB_OK|MB_ICONSTOP "需要 Windows 11 x64（build 22000 或更高版本）。安装已终止。"
  Abort

windows_supported:
  ReadRegStr $0 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion" "InstallationType"
  ${If} $0 != "Client"
    MessageBox MB_OK|MB_ICONSTOP "Windows Server 或非客户端 edition 不属于 V1 支持范围。安装已终止。"
    Abort
  ${EndIf}
  ReadRegStr $0 HKLM "SOFTWARE\Microsoft\Windows NT\CurrentVersion" "ProductName"
  ${If} $0 == ""
    MessageBox MB_OK|MB_ICONSTOP "无法核验 Windows edition。安装已终止。"
    Abort
  ${EndIf}

  System::Call 'kernel32::GetDiskFreeSpaceExW(w "$LOCALAPPDATA", *l .r0, *l .r1, *l .r2)i .r3'
  ${If} $3 == 0
    MessageBox MB_OK|MB_ICONSTOP "无法核验安装卷可用空间。安装已终止。"
    Abort
  ${EndIf}
  System::Int64Op $0 / 1073741824
  Pop $1
  IntCmp $1 1 install_disk_ok install_disk_low install_disk_ok

install_disk_low:
  MessageBox MB_OK|MB_ICONSTOP "安装卷至少需要 1 GiB 当前可用空间；运行前 Launcher 还会执行 40 GiB 数据安全水位检查。"
  Abort

install_disk_ok:
  ReadRegStr $4 HKCU "${UNINSTALL_KEY}" "DisplayVersion"
  ${If} $4 != ""
    ${VersionCompare} $4 "${PRODUCT_VERSION}" $5
    ${If} $5 == 1
      MessageBox MB_OK|MB_ICONSTOP "检测到较新版本 $4。禁止安装 ${PRODUCT_VERSION} 降级覆盖。"
      Abort
    ${ElseIf} $5 == 2
      MessageBox MB_OK|MB_ICONSTOP "检测到旧版本 $4。当前骨架尚未交付升级前备份/迁移闭环，已安全阻断覆盖升级；请等待兼容升级程序。"
      Abort
    ${EndIf}
  ${EndIf}
FunctionEnd

Function StopExistingSameVersion
  ReadRegStr $0 HKCU "${UNINSTALL_KEY}" "DisplayVersion"
  ${If} $0 != "${PRODUCT_VERSION}"
    Return
  ${EndIf}
  ReadRegStr $1 HKCU "${PRODUCT_KEY}" "InstallDir"
  ${If} $1 != "${INSTALL_DIRECTORY}"
    MessageBox MB_OK|MB_ICONSTOP "现有版本安装路径不是固定每用户目录，无法安全覆盖。"
    Abort
  ${EndIf}
  Call AssertInstallationPathsNoReparse
  Call AssertInstalledLeavesNoReparse
  IfFileExists "$1\launcher.exe" 0 existing_launcher_missing
  ExecWait '"$1\launcher.exe" stop' $2
  ${If} $2 != 0
    MessageBox MB_OK|MB_ICONSTOP "现有同版本服务未能安全停止，安装已取消。"
    Abort
  ${EndIf}
  Return

existing_launcher_missing:
  MessageBox MB_OK|MB_ICONSTOP "现有同版本缺少 launcher.exe，无法安全覆盖。"
  Abort
FunctionEnd

Section "DataX Enterprise Studio" SEC_MAIN
  SectionIn RO
  SetRegView 64
  SetShellVarContext current
  SetOverwrite on
  AllowSkipFiles off

  SetOutPath "$PLUGINSDIR\release-check"
  File "/oname=launcher.exe" "${LAUNCHER_EXE}"
  SetOutPath "$PLUGINSDIR\release-check\resources"
  File "/oname=compose.yaml" "${COMPOSE_FILE}"
  File "/oname=images.release.env" "${IMAGE_ENV_FILE}"
  File "/oname=secure-acl.ps1" "${ACL_SCRIPT}"
  File "/oname=release-manifest.json" "${RELEASE_MANIFEST}"
  ExecWait '"$PLUGINSDIR\release-check\launcher.exe" verify-release --installer "$EXEPATH"' $0
  ${If} $0 != 0
    MessageBox MB_OK|MB_ICONSTOP \
      "Setup、Launcher 或发布资源的签名身份/完整性核验失败。安装已安全终止，未写入程序目录。"
    Abort
  ${EndIf}

  ; Preserve a healthy existing same-version installation until the incoming
  ; Setup, Launcher, and resources have passed their complete detached check.
  Call StopExistingSameVersion

  ; Installed release resources are intentionally read-only. A same-version
  ; repair must clear that attribute explicitly and fail rather than allowing a
  ; user to skip a resource whose replacement could not be written.
  Call NormalizeExistingResourceAttributes

  Call AssertInstallationPathsNoReparse
  Call AssertInstalledLeavesNoReparse
  SetOutPath "$INSTDIR"
  ; SetOutPath can create a previously missing directory. Re-check the full
  ; tree before the first File write. This is a stable-path guard only: an
  ; NSIS path check cannot close a hostile same-user TOCTOU race.
  Call AssertInstallationPathsNoReparse
  Call AssertInstalledLeavesNoReparse
  File "/oname=launcher.exe" "${LAUNCHER_EXE}"

  Call AssertInstallationPathsNoReparse
  Call AssertInstalledLeavesNoReparse
  SetOutPath "$INSTDIR\resources"
  Call AssertInstallationPathsNoReparse
  Call AssertInstalledLeavesNoReparse
  File "/oname=compose.yaml" "${COMPOSE_FILE}"
  File "/oname=images.release.env" "${IMAGE_ENV_FILE}"
  File "/oname=secure-acl.ps1" "${ACL_SCRIPT}"
  File "/oname=release-manifest.json" "${RELEASE_MANIFEST}"
  Call AssertInstallationPathsNoReparse
  Call AssertInstalledLeavesNoReparse
  SetFileAttributes "$INSTDIR\resources\compose.yaml" READONLY
  SetFileAttributes "$INSTDIR\resources\images.release.env" READONLY
  SetFileAttributes "$INSTDIR\resources\secure-acl.ps1" READONLY
  SetFileAttributes "$INSTDIR\resources\release-manifest.json" READONLY

  Call AssertInstallationPathsNoReparse
  Call AssertInstalledLeavesNoReparse
  SetOutPath "$INSTDIR"
  Call AssertInstallationPathsNoReparse
  Call AssertInstalledLeavesNoReparse
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  CreateDirectory "$SMPROGRAMS\${START_MENU_DIR}"
  CreateShortCut "$DESKTOP\DataX Enterprise Studio.lnk" \
    "$INSTDIR\launcher.exe" "" "$INSTDIR\launcher.exe" 0
  CreateShortCut "$SMPROGRAMS\${START_MENU_DIR}\启动 DataX Enterprise Studio.lnk" \
    "$INSTDIR\launcher.exe" "" "$INSTDIR\launcher.exe" 0
  CreateShortCut "$SMPROGRAMS\${START_MENU_DIR}\安全停止 DataX Enterprise Studio.lnk" \
    "$INSTDIR\launcher.exe" "stop" "$INSTDIR\launcher.exe" 0
  CreateShortCut "$SMPROGRAMS\${START_MENU_DIR}\卸载.lnk" \
    "$INSTDIR\Uninstall.exe"

  WriteRegStr HKCU "${PRODUCT_KEY}" "InstallDir" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayName" "${PRODUCT_NAME}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayVersion" "${PRODUCT_VERSION}"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "DisplayIcon" "$INSTDIR\launcher.exe"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "Publisher" "DataX Enterprise Studio"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINSTALL_KEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINSTALL_KEY}" "NoRepair" 1

  MessageBox MB_OK|MB_ICONINFORMATION \
    "安装完成。$\r$\n$\r$\n本安装包不包含、不安装或配置 Docker Desktop/WSL2，也不会替您接受第三方条款。首次启动前，请从官方渠道完成这些依赖。"
SectionEnd

Function un.onInit
  ; Uninstall also requires an interactive acknowledgement before deleting
  ; program files. Use the NSIS state, which includes the /S switch.
  IfSilent uninstaller_silent_rejected uninstaller_interactive

uninstaller_silent_rejected:
  SetErrorLevel 2
  Abort

uninstaller_interactive:
  SetRegView 64
  SetShellVarContext current

  ; NSIS may execute an uninstaller from a temporary self-copy. Resolve the
  ; only supported target from the persisted install record, then bind $INSTDIR
  ; back to the fixed per-user root before any stop or delete operation.
  ReadRegStr $0 HKCU "${PRODUCT_KEY}" "InstallDir"
  ${If} $0 != "${INSTALL_DIRECTORY}"
    MessageBox MB_OK|MB_ICONSTOP "无法证明这是当前用户受支持的 DataX Enterprise Studio 安装目录；为避免删除错误路径，卸载已终止。"
    Abort
  ${EndIf}
  StrCpy $INSTDIR "${INSTALL_DIRECTORY}"
  Call AssertInstallationPathsNoReparse
  Call AssertInstalledLeavesNoReparse

  MessageBox MB_YESNO|MB_ICONEXCLAMATION|MB_DEFBUTTON2 \
    "卸载只删除当前用户的程序文件和快捷方式。$\r$\n$\r$\n以下内容会保留：$\r$\n%LOCALAPPDATA%\DataXEnterpriseStudio$\r$\nDocker named volumes（包括数据库、日志和工作目录）。$\r$\n$\r$\n继续前，卸载程序会尝试安全停止服务；存在活动 Attempt 时会拒绝卸载。是否继续？" \
    IDYES continue_uninstall
  Abort

continue_uninstall:
  IfFileExists "$INSTDIR\launcher.exe" 0 launcher_absent
  ExecWait '"$INSTDIR\launcher.exe" stop' $0
  ${If} $0 != 0
    ${If} $0 == 3
      MessageBox MB_OK|MB_ICONSTOP \
        "安全停止被活动 Attempt 阻断，卸载已取消。请等待任务结束或先在 Launcher 中显式取消；如确需中断，必须先单独执行带风险确认的强制停止。"
      Abort
    ${EndIf}
    MessageBox MB_YESNO|MB_ICONEXCLAMATION|MB_DEFBUTTON2 \
      "无法证明服务已安全停止，原因可能是活动 Attempt、Docker Desktop 缺失/离线或安装资源损坏。$\r$\n$\r$\n继续只会删除程序文件并保留全部本地数据与 Docker named volumes；容器可能仍在运行，之后需恢复同版本 Launcher 或由管理员处置。仍要继续吗？" \
      IDYES launcher_stop_unverified
    Abort
  ${EndIf}
  Goto launcher_stop_verified

launcher_absent:
  MessageBox MB_YESNO|MB_ICONEXCLAMATION|MB_DEFBUTTON2 \
    "launcher.exe 不存在，无法确认容器是否已停止。继续只删除程序文件并保留数据；容器可能仍在运行。仍要继续吗？" \
    IDYES launcher_stop_unverified
  Abort

launcher_stop_unverified:
  MessageBox MB_OK|MB_ICONEXCLAMATION \
    "将继续卸载程序，但服务停止状态未经验证。不会删除 %LOCALAPPDATA%\DataXEnterpriseStudio 或 Docker named volumes。"

launcher_stop_verified:
FunctionEnd

Function NormalizeExistingResourceAttributes
  Call AssertInstallationPathsNoReparse
  Call AssertInstalledLeavesNoReparse
  IfFileExists "$INSTDIR\resources\compose.yaml" 0 normalize_images
  ClearErrors
  SetFileAttributes "$INSTDIR\resources\compose.yaml" NORMAL
  IfErrors normalize_failed

normalize_images:
  IfFileExists "$INSTDIR\resources\images.release.env" 0 normalize_acl
  ClearErrors
  SetFileAttributes "$INSTDIR\resources\images.release.env" NORMAL
  IfErrors normalize_failed

normalize_acl:
  IfFileExists "$INSTDIR\resources\secure-acl.ps1" 0 normalize_manifest
  ClearErrors
  SetFileAttributes "$INSTDIR\resources\secure-acl.ps1" NORMAL
  IfErrors normalize_failed

normalize_manifest:
  IfFileExists "$INSTDIR\resources\release-manifest.json" 0 normalize_complete
  ClearErrors
  SetFileAttributes "$INSTDIR\resources\release-manifest.json" NORMAL
  IfErrors normalize_failed

normalize_complete:
  Return

normalize_failed:
  MessageBox MB_OK|MB_ICONSTOP "无法解除现有发布资源的只读属性，无法安全完成同版本修复。安装已终止。"
  Abort
FunctionEnd

Function AssertPathNotReparseOrMissing
  ; Input: absolute path. Output: PRESENT or MISSING. Any other attribute
  ; query failure or a reparse point aborts before a later path mutation.
  Exch $0
  Push $1
  Push $2
  System::Call 'kernel32::GetFileAttributesW(w r0)i .r1?e'
  Pop $2

  ${If} $1 == ${DES_INVALID_FILE_ATTRIBUTES}
    ${If} $2 == ${DES_ERROR_FILE_NOT_FOUND}
      StrCpy $0 "MISSING"
      Goto assert_path_not_reparse_complete
    ${ElseIf} $2 == ${DES_ERROR_PATH_NOT_FOUND}
      StrCpy $0 "MISSING"
      Goto assert_path_not_reparse_complete
    ${Else}
      MessageBox MB_OK|MB_ICONSTOP "无法安全读取安装路径属性。安装或卸载已终止。"
      Abort
    ${EndIf}
  ${EndIf}

  IntOp $2 $1 & ${DES_FILE_ATTRIBUTE_REPARSE_POINT}
  ${If} $2 != 0
    MessageBox MB_OK|MB_ICONSTOP "检测到安装目录或发布资源为重解析点（junction/symlink）。安装或卸载已终止。"
    Abort
  ${EndIf}
  StrCpy $0 "PRESENT"

assert_path_not_reparse_complete:
  Pop $2
  Pop $1
  Exch $0
FunctionEnd

Function AssertInstallationPathsNoReparse
  ; %LOCALAPPDATA% itself must be present. The child directories may be absent
  ; on a first install and are re-checked after SetOutPath creates them.
  Push "$LOCALAPPDATA"
  Call AssertPathNotReparseOrMissing
  Pop $0
  ${If} $0 == "MISSING"
    MessageBox MB_OK|MB_ICONSTOP "无法定位当前用户的 LocalAppData 目录。安装或卸载已终止。"
    Abort
  ${EndIf}

  Push "$LOCALAPPDATA\Programs"
  Call AssertPathNotReparseOrMissing
  Pop $0
  Push "$INSTDIR"
  Call AssertPathNotReparseOrMissing
  Pop $0
  Push "$INSTDIR\resources"
  Call AssertPathNotReparseOrMissing
  Pop $0
FunctionEnd

Function AssertInstalledLeavesNoReparse
  ; Existing leaves can otherwise cause a repair File/WriteUninstaller write
  ; or an uninstall operation to follow a reparse point outside the root.
  Push "$INSTDIR\launcher.exe"
  Call AssertPathNotReparseOrMissing
  Pop $0
  Push "$INSTDIR\resources\compose.yaml"
  Call AssertPathNotReparseOrMissing
  Pop $0
  Push "$INSTDIR\resources\images.release.env"
  Call AssertPathNotReparseOrMissing
  Pop $0
  Push "$INSTDIR\resources\secure-acl.ps1"
  Call AssertPathNotReparseOrMissing
  Pop $0
  Push "$INSTDIR\resources\release-manifest.json"
  Call AssertPathNotReparseOrMissing
  Pop $0
  Push "$INSTDIR\Uninstall.exe"
  Call AssertPathNotReparseOrMissing
  Pop $0
FunctionEnd

Section "Uninstall"
  SetRegView 64
  SetShellVarContext current

  Call AssertInstallationPathsNoReparse
  Call AssertInstalledLeavesNoReparse

  Delete "$DESKTOP\DataX Enterprise Studio.lnk"
  Delete "$SMPROGRAMS\${START_MENU_DIR}\启动 DataX Enterprise Studio.lnk"
  Delete "$SMPROGRAMS\${START_MENU_DIR}\安全停止 DataX Enterprise Studio.lnk"
  Delete "$SMPROGRAMS\${START_MENU_DIR}\卸载.lnk"
  RMDir "$SMPROGRAMS\${START_MENU_DIR}"

  SetFileAttributes "$INSTDIR\resources\compose.yaml" NORMAL
  SetFileAttributes "$INSTDIR\resources\images.release.env" NORMAL
  SetFileAttributes "$INSTDIR\resources\secure-acl.ps1" NORMAL
  SetFileAttributes "$INSTDIR\resources\release-manifest.json" NORMAL
  Delete "$INSTDIR\resources\compose.yaml"
  Delete "$INSTDIR\resources\images.release.env"
  Delete "$INSTDIR\resources\secure-acl.ps1"
  Delete "$INSTDIR\resources\release-manifest.json"
  RMDir "$INSTDIR\resources"
  Delete "$INSTDIR\launcher.exe"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir "$INSTDIR"

  DeleteRegKey HKCU "${UNINSTALL_KEY}"
  DeleteRegKey HKCU "${PRODUCT_KEY}"

  MessageBox MB_OK|MB_ICONINFORMATION \
    "程序已卸载。本地数据目录和 Docker named volumes 已保留；如需删除数据，请另行执行经确认的数据清理流程。"
SectionEnd
