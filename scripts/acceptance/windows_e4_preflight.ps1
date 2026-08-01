[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')]
    [string]$ReleaseCandidate,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-f0-9]{40}$')]
    [string]$CommitSha,
    [Parameter(Mandatory = $true)]
    [string]$SetupPath,
    [Parameter(Mandatory = $true)]
    [string]$LauncherPath,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-f0-9]{64}$')]
    [string]$ExpectedSetupSha256,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-f0-9]{64}$')]
    [string]$ExpectedLauncherSha256,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[a-f0-9]{64}$')]
    [string]$ExpectedSignerCertificateDerSha256,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')]
    [string]$BaselineId,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$')]
    [string]$RunnerId,
    [Parameter(Mandatory = $true)]
    [string]$OutputPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# This script is deliberately a local, read-mostly preflight.  It never runs
# Setup, Docker Compose, DataX, a browser, or a database test; it never enables
# Windows/WSL features or accepts Docker Desktop terms.  Its output is fixed to
# E4=NOT_RUN and release_approved=false.
$script:Checks = @()
$script:LocalReady = $true

function Add-PreflightCheck {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Id,
        [Parameter(Mandatory = $true)]
        [bool]$Passed,
        [Parameter(Mandatory = $true)]
        [string]$Detail
    )

    $script:Checks += [ordered]@{
        check_id = $Id
        result = if ($Passed) { "PASS" } else { "BLOCKED" }
        detail = $Detail
    }
    if (-not $Passed) {
        $script:LocalReady = $false
    }
}

function Get-LocalFixedDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    try {
        $fullPath = [IO.Path]::GetFullPath($Path)
    }
    catch {
        throw "$Description path is invalid."
    }
    if ($fullPath -notmatch '^[A-Za-z]:\\') {
        throw "$Description must be on a local fixed Windows volume."
    }
    $drive = $fullPath.Substring(0, 2)
    try {
        $disk = Get-CimInstance `
            -ClassName Win32_LogicalDisk `
            -Filter "DeviceID='$drive'" `
            -ErrorAction Stop
    }
    catch {
        throw "$Description must be on a local fixed Windows volume."
    }
    if ($null -eq $disk -or [int]$disk.DriveType -ne 3) {
        throw "$Description must be on a local fixed Windows volume."
    }
    $root = [IO.Path]::GetPathRoot($fullPath)
    $current = $root
    $item = Get-Item -LiteralPath $root -Force -ErrorAction Stop
    foreach ($segment in ($fullPath.Substring($root.Length) -split '[\\/]')) {
        if ([string]::IsNullOrWhiteSpace($segment)) {
            continue
        }
        $current = Join-Path -Path $current -ChildPath $segment
        try {
            $item = Get-Item -LiteralPath $current -Force -ErrorAction Stop
        }
        catch {
            throw "$Description path cannot be accessed."
        }
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "$Description path must not contain a reparse point."
        }
    }
    if (-not $item.PSIsContainer) {
        throw "$Description must be a directory."
    }
    return $item
}

function Get-LocalRegularFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    try {
        $fullPath = [IO.Path]::GetFullPath($Path)
    }
    catch {
        throw "$Description path is invalid."
    }
    $parent = Split-Path -Parent $fullPath
    if ([string]::IsNullOrWhiteSpace($parent)) {
        throw "$Description must be a regular file."
    }
    Get-LocalFixedDirectory -Path $parent -Description "$Description parent" | Out-Null
    try {
        $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    }
    catch {
        throw "$Description file cannot be accessed."
    }
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Description must be a non-reparse regular file."
    }
    return $item
}

function Get-Sha256 {
    param(
        [Parameter(Mandatory = $true)]
        [IO.FileInfo]$File
    )

    return (Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-CertificateDerSha256 {
    param(
        [Parameter(Mandatory = $true)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
            $algorithm.ComputeHash($Certificate.RawData)
        ).Replace("-", "")).ToLowerInvariant()
    }
    finally {
        $algorithm.Dispose()
    }
}

function New-EmptyCandidateArtifact {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ExpectedSha256
    )

    return [ordered]@{
        file_name = $null
        sha256 = $null
        expected_sha256 = $ExpectedSha256
        hash_matches = $false
        authenticode_status = "UNAVAILABLE"
        signer_certificate_der_sha256 = $null
        signer_matches = $false
        timestamp_present = $false
    }
}

function Get-CandidateArtifactObservation {
    param(
        [Parameter(Mandatory = $true)]
        [IO.FileInfo]$File,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedSha256,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedSignerDerSha256
    )

    $sha256 = Get-Sha256 -File $File
    $signature = Get-AuthenticodeSignature -LiteralPath $File.FullName
    $certificateDerSha256 = $null
    $signerMatches = $false
    if ($null -ne $signature.SignerCertificate) {
        $certificateDerSha256 = Get-CertificateDerSha256 `
            -Certificate $signature.SignerCertificate
        $signerMatches = $certificateDerSha256 -ceq $ExpectedSignerDerSha256
    }
    return [ordered]@{
        file_name = $File.Name
        sha256 = $sha256
        expected_sha256 = $ExpectedSha256
        hash_matches = ($sha256 -ceq $ExpectedSha256)
        authenticode_status = if (
            $signature.Status -eq [Management.Automation.SignatureStatus]::Valid
        ) { "VALID" } else { "INVALID" }
        signer_certificate_der_sha256 = $certificateDerSha256
        signer_matches = $signerMatches
        timestamp_present = ($null -ne $signature.TimeStamperCertificate)
    }
}

function Invoke-IsolatedDocker {
    param(
        [Parameter(Mandatory = $true)]
        [string]$DockerPath,
        [Parameter(Mandatory = $true)]
        [string]$Endpoint,
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $configDirectory = Join-Path `
        ([IO.Path]::GetTempPath()) `
        ("datax-e4-preflight-" + [Guid]::NewGuid().ToString("N"))
    try {
        $directory = New-Item `
            -ItemType Directory `
            -Path $configDirectory `
            -ErrorAction Stop
        if ($directory.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw "Temporary Docker configuration directory is a reparse point."
        }
        $encoding = New-Object -TypeName Text.UTF8Encoding -ArgumentList $false
        [IO.File]::WriteAllText(
            (Join-Path $configDirectory "config.json"),
            '{"auths":{}}',
            $encoding
        )
        $dockerArguments = @(
            "--config", $configDirectory,
            "--host", $Endpoint
        ) + $Arguments
        $output = @(& $DockerPath @dockerArguments 2>&1)
        $result = [ordered]@{
            exit_code = $LASTEXITCODE
            output = (($output | ForEach-Object { [string]$_ }) -join "`n").Trim()
        }
        Write-Output -NoEnumerate $result
    }
    finally {
        if (Test-Path -LiteralPath $configDirectory) {
            Remove-Item -LiteralPath $configDirectory -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Write-PreflightDocument {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [object]$Document
    )

    try {
        $fullPath = [IO.Path]::GetFullPath($Path)
    }
    catch {
        throw "Preflight output path is invalid."
    }
    $parent = Split-Path -Parent $fullPath
    if ([string]::IsNullOrWhiteSpace($parent)) {
        throw "Preflight output path has no parent directory."
    }
    Get-LocalFixedDirectory -Path $parent -Description "Preflight output parent" | Out-Null
    if (Test-Path -LiteralPath $fullPath) {
        throw "Preflight output already exists; refusing to overwrite evidence."
    }
    $json = $Document | ConvertTo-Json -Depth 12 -Compress
    $encoding = New-Object -TypeName Text.UTF8Encoding -ArgumentList $false
    $stream = [IO.File]::Open(
        $fullPath,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try {
        $bytes = $encoding.GetBytes($json)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

$windows = [ordered]@{
    edition = "UNKNOWN"
    product_type = "UNKNOWN"
    build = "UNKNOWN"
    architecture = "OTHER"
    secure_boot_enabled = $null
    virtualization_firmware_enabled = $null
    hypervisor_present = $null
}
try {
    $operatingSystem = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
    $processor = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop |
        Select-Object -First 1
    $isWindows11 = $operatingSystem.Caption -match 'Windows 11'
    $isClient = [int]$operatingSystem.ProductType -eq 1
    $isX64 = $env:PROCESSOR_ARCHITECTURE -eq "AMD64" -and
        [int]$processor.AddressWidth -eq 64
    $windows.edition = if ($isWindows11) { "Windows 11" } else { $operatingSystem.Caption }
    $windows.product_type = if ($isClient) { "CLIENT" } else { "SERVER_OR_OTHER" }
    $windows.build = [string]$operatingSystem.BuildNumber
    $windows.architecture = if ($isX64) { "X86_64" } else { "OTHER" }
    $windows.hypervisor_present = [bool]$computerSystem.HypervisorPresent
    if ($null -ne $processor.PSObject.Properties["VirtualizationFirmwareEnabled"]) {
        $windows.virtualization_firmware_enabled = [bool]$processor.VirtualizationFirmwareEnabled
    }
    try {
        $windows.secure_boot_enabled = [bool](Confirm-SecureBootUEFI -ErrorAction Stop)
    }
    catch {
        $windows.secure_boot_enabled = $null
    }
    Add-PreflightCheck `
        -Id "WIN11_X64_CLIENT" `
        -Passed ($isWindows11 -and $isClient -and $isX64) `
        -Detail "Windows client edition and native architecture were observed."
    Add-PreflightCheck `
        -Id "VIRTUALIZATION" `
        -Passed ($windows.virtualization_firmware_enabled -eq $true) `
        -Detail "Firmware virtualization was observed without changing firmware or Windows features."
}
catch {
    Add-PreflightCheck `
        -Id "WIN11_X64_CLIENT" `
        -Passed $false `
        -Detail "Windows edition or architecture could not be observed."
    Add-PreflightCheck `
        -Id "VIRTUALIZATION" `
        -Passed $false `
        -Detail "Firmware virtualization could not be observed."
}

$docker = [ordered]@{
    ambient_context_absent = $false
    wsl_default_version = $null
    wsl_status_available = $false
    desktop_install_detected = $false
    engine_available = $false
    server_os = $null
    server_architecture = $null
    compose_version = $null
}
$ambientContextAbsent = [string]::IsNullOrWhiteSpace(
    [Environment]::GetEnvironmentVariable("DOCKER_HOST", [EnvironmentVariableTarget]::Process)
) -and [string]::IsNullOrWhiteSpace(
    [Environment]::GetEnvironmentVariable("DOCKER_CONTEXT", [EnvironmentVariableTarget]::Process)
)
$docker.ambient_context_absent = $ambientContextAbsent
Add-PreflightCheck `
    -Id "DOCKER_AMBIENT_CONTEXT" `
    -Passed $ambientContextAbsent `
    -Detail "The preflight refuses to query a caller-selected Docker host or context."

try {
    $wslPath = Get-LocalRegularFile `
        -Path (Join-Path $env:SystemRoot "System32\\wsl.exe") `
        -Description "wsl.exe"
    $null = @(& $wslPath.FullName --status 2>&1)
    $docker.wsl_status_available = $LASTEXITCODE -eq 0
    $defaultVersion = Get-ItemPropertyValue `
        -LiteralPath "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Lxss" `
        -Name "DefaultVersion" `
        -ErrorAction Stop
    $docker.wsl_default_version = [int]$defaultVersion
}
catch {
    $docker.wsl_status_available = $false
    $docker.wsl_default_version = $null
}
Add-PreflightCheck `
    -Id "WSL2_DEFAULT" `
    -Passed ($docker.wsl_status_available -and $docker.wsl_default_version -eq 2) `
    -Detail "WSL was observed only; this preflight never calls wsl --install or changes the default version."

$dockerPath = $null
$composePath = $null
try {
    $desktopInstallPath = (Get-ItemProperty `
        -LiteralPath "HKLM:\\SOFTWARE\\Docker Inc.\\Docker Desktop" `
        -Name "InstallPath" `
        -ErrorAction Stop).InstallPath
    if ([string]::IsNullOrWhiteSpace($desktopInstallPath)) {
        throw "Docker Desktop installation record is empty."
    }
    $dockerPath = (Get-LocalRegularFile `
        -Path (Join-Path $desktopInstallPath "resources\\bin\\docker.exe") `
        -Description "Docker Desktop docker.exe").FullName
    $composePath = (Get-LocalRegularFile `
        -Path (Join-Path $desktopInstallPath "resources\\cli-plugins\\docker-compose.exe") `
        -Description "Docker Desktop docker-compose.exe").FullName
    $docker.desktop_install_detected = $true
}
catch {
    $docker.desktop_install_detected = $false
}

$activeEndpoint = $null
if ($ambientContextAbsent -and $null -ne $dockerPath) {
    foreach ($endpoint in @(
        "npipe:////./pipe/docker_engine",
        "npipe:////./pipe/dockerdesktoplinuxengine"
    )) {
        try {
            $version = Invoke-IsolatedDocker `
                -DockerPath $dockerPath `
                -Endpoint $endpoint `
                -Arguments @("version", "--format", "{{.Server.Os}}|{{.Server.Arch}}")
            if ($version.exit_code -eq 0 -and $version.output -match '^linux\\|amd64$') {
                $docker.engine_available = $true
                $docker.server_os = "linux"
                $docker.server_architecture = "amd64"
                $activeEndpoint = $endpoint
                break
            }
        }
        catch {
            # The final check below records the safe blocked outcome without
            # leaking a user-controlled path or Docker diagnostic into JSON.
        }
    }
}
Add-PreflightCheck `
    -Id "DOCKER_DESKTOP_LINUX_AMD64" `
    -Passed ($docker.desktop_install_detected -and $docker.engine_available) `
    -Detail "Only Docker Desktop's local Linux/amd64 endpoint was probed with an ephemeral empty CLI config."

if ($null -ne $composePath -and $ambientContextAbsent) {
    try {
        $composeOutput = @(& $composePath version --short 2>&1)
        if ($LASTEXITCODE -eq 0) {
            $versionText = (($composeOutput | ForEach-Object { [string]$_ }) -join "").Trim()
            if (-not [string]::IsNullOrWhiteSpace($versionText)) {
                $docker.compose_version = $versionText.Substring(
                    0,
                    [Math]::Min(128, $versionText.Length)
                )
            }
        }
    }
    catch {
        $docker.compose_version = $null
    }
}
Add-PreflightCheck `
    -Id "DOCKER_COMPOSE_V2" `
    -Passed (-not [string]::IsNullOrWhiteSpace($docker.compose_version)) `
    -Detail "The fixed Docker Desktop Compose plugin was queried for its version only."

$candidate = [ordered]@{
    expected_signer_certificate_der_sha256 = $ExpectedSignerCertificateDerSha256
    setup = New-EmptyCandidateArtifact -ExpectedSha256 $ExpectedSetupSha256
    launcher = New-EmptyCandidateArtifact -ExpectedSha256 $ExpectedLauncherSha256
}
try {
    $setup = Get-LocalRegularFile -Path $SetupPath -Description "Setup candidate"
    $launcher = Get-LocalRegularFile -Path $LauncherPath -Description "Launcher candidate"
    $candidate.setup = Get-CandidateArtifactObservation `
        -File $setup `
        -ExpectedSha256 $ExpectedSetupSha256 `
        -ExpectedSignerDerSha256 $ExpectedSignerCertificateDerSha256
    $candidate.launcher = Get-CandidateArtifactObservation `
        -File $launcher `
        -ExpectedSha256 $ExpectedLauncherSha256 `
        -ExpectedSignerDerSha256 $ExpectedSignerCertificateDerSha256
}
catch {
    # The two checks below capture the failure without storing arbitrary path
    # text or command output in the machine-readable evidence document.
}
$hashesMatch = $candidate.setup.hash_matches -and $candidate.launcher.hash_matches
$signaturesMatch = $candidate.setup.authenticode_status -eq "VALID" -and
    $candidate.launcher.authenticode_status -eq "VALID" -and
    $candidate.setup.signer_matches -and
    $candidate.launcher.signer_matches -and
    $candidate.setup.timestamp_present -and
    $candidate.launcher.timestamp_present
Add-PreflightCheck `
    -Id "CANDIDATE_HASHES" `
    -Passed $hashesMatch `
    -Detail "Setup and Launcher SHA-256 values were compared with externally supplied expected values."
Add-PreflightCheck `
    -Id "CANDIDATE_SIGNATURES" `
    -Passed $signaturesMatch `
    -Detail "Setup and Launcher Authenticode observations must match the externally supplied signer certificate DER SHA-256."

$productStateAbsent = $null
if ($null -ne $activeEndpoint) {
    try {
        $applicationData = Join-Path $env:LOCALAPPDATA "DataXEnterpriseStudio"
        $installationRoot = Join-Path `
            $env:LOCALAPPDATA `
            "Programs\\DataXEnterpriseStudio"
        $volumeResult = Invoke-IsolatedDocker `
            -DockerPath $dockerPath `
            -Endpoint $activeEndpoint `
            -Arguments @(
                "volume", "ls", "--quiet", "--filter",
                "label=com.xiaoli.datax.volume-role"
            )
        $productVolumes = @()
        if ($volumeResult.exit_code -eq 0) {
            $productVolumes = @(
                $volumeResult.output -split "`r?`n" |
                    Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
            )
        }
        $productStateAbsent = -not (Test-Path -LiteralPath $applicationData) -and
            -not (Test-Path -LiteralPath $installationRoot) -and
            $volumeResult.exit_code -eq 0 -and
            $productVolumes.Count -eq 0
    }
    catch {
        $productStateAbsent = $null
    }
}
Add-PreflightCheck `
    -Id "PRODUCT_STATE_ABSENT" `
    -Passed ($productStateAbsent -eq $true) `
    -Detail "Only fixed product paths and labelled product volumes were observed; this is not proof that the VM is clean."

$document = [ordered]@{
    schema_version = "1.0"
    artifact_kind = "WINDOWS_E4_HARNESS_PREFLIGHT"
    local_preflight_result = if ($script:LocalReady) { "READY" } else { "BLOCKED" }
    e4_result = "NOT_RUN"
    release_approved = $false
    captured_at = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    release_candidate = $ReleaseCandidate
    commit_sha = $CommitSha
    harness_version = "windows-e4-preflight/v1"
    baseline = [ordered]@{
        baseline_id = $BaselineId
        independently_verified = $false
    }
    runner = [ordered]@{
        runner_id = $RunnerId
        self_hosted_registration_verified = $false
    }
    windows = $windows
    docker = $docker
    candidate = $candidate
    product_state_absent = $productStateAbsent
    checks = @($script:Checks)
    limitations = @(
        "Local prerequisite observations do not prove that the VM was restored from an approved golden image.",
        "The script does not verify self-hosted runner registration, runner-group isolation, approval, or operator separation.",
        "The script never runs Setup, Docker Compose, DataX, browser, database, recovery, LAN-peer, sleep, restart, or uninstall scenarios.",
        "E4 remains NOT_RUN and release_approved remains false until a separate protected harness, scenario contract, evidence validator, and release-promotion chain are implemented."
    )
}

Write-PreflightDocument -Path $OutputPath -Document $document
if ($script:LocalReady) {
    exit 0
}
exit 2
