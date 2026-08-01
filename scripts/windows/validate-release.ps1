[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$CandidateDirectory,
    [Parameter(Mandatory = $true)]
    [string]$SetupPath,
    [Parameter(Mandatory = $true)]
    [string]$LauncherPath,
    [Parameter(Mandatory = $true)]
    [string]$ImagesReleaseFile,
    [Parameter(Mandatory = $true)]
    [string]$ReleaseContextFile,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9A-Fa-f]{40}$')]
    [string]$ExpectedSignerThumbprint,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$')]
    [string]$ExpectedVersion,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$ExpectedCommit,
    [string]$SigntoolPath
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

function Resolve-RequiredFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $resolved = Resolve-Path -LiteralPath $Path -ErrorAction Stop
    $item = Get-Item -LiteralPath $resolved.Path -Force
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$Description must be a non-reparse regular file."
    }
    return $item
}

function Resolve-RequiredCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [string]$ExplicitPath
    )

    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        return (Resolve-RequiredFile -Path $ExplicitPath -Description $Name).FullName
    }
    $command = Get-Command -Name $Name -CommandType Application -ErrorAction Stop
    return (Resolve-RequiredFile -Path $command.Source -Description $Name).FullName
}

function Assert-ChildOfCandidate {
    param(
        [Parameter(Mandatory = $true)]
        [IO.FileInfo]$Item,
        [Parameter(Mandatory = $true)]
        [string]$RootPrefix
    )

    if (-not $Item.FullName.StartsWith(
        $RootPrefix,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Release evidence file is outside CandidateDirectory."
    }
}

function Test-TrustedCertificateChain {
    param(
        [Parameter(Mandatory = $true)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $chain = [Security.Cryptography.X509Certificates.X509Chain]::new()
    try {
        $chain.ChainPolicy.RevocationMode =
            [Security.Cryptography.X509Certificates.X509RevocationMode]::Online
        $chain.ChainPolicy.RevocationFlag =
            [Security.Cryptography.X509Certificates.X509RevocationFlag]::ExcludeRoot
        $chain.ChainPolicy.VerificationFlags =
            [Security.Cryptography.X509Certificates.X509VerificationFlags]::NoFlag
        $chain.ChainPolicy.UrlRetrievalTimeout = [TimeSpan]::FromSeconds(30)
        if (-not $chain.Build($Certificate)) {
            $statuses = @(
                $chain.ChainStatus |
                    ForEach-Object { $_.Status.ToString() }
            ) -join ","
            throw "$Description certificate chain is not trusted: $statuses"
        }
    }
    finally {
        $chain.Dispose()
    }
}

function Get-VerifiedSignatureEvidence {
    param(
        [Parameter(Mandatory = $true)]
        [IO.FileInfo]$File,
        [Parameter(Mandatory = $true)]
        [string]$ExpectedThumbprint,
        [Parameter(Mandatory = $true)]
        [string]$Signtool,
        [Parameter(Mandatory = $true)]
        [string]$SigntoolEvidencePath
    )

    if (Test-Path -LiteralPath $SigntoolEvidencePath) {
        throw "Signature verification evidence path already exists."
    }
    $signtoolOutput = @(& $Signtool verify /pa /all /v $File.FullName 2>&1)
    $signtoolExitCode = $LASTEXITCODE
    [IO.File]::WriteAllLines(
        $SigntoolEvidencePath,
        @($signtoolOutput | ForEach-Object { [string]$_ }),
        [Text.UTF8Encoding]::new($false)
    )
    if ($signtoolExitCode -ne 0) {
        throw "signtool verification failed for $($File.Name)."
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $File.FullName
    if ($signature.Status -ne [Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate) {
        throw "Authenticode verification failed for $($File.Name)."
    }
    $signer = $signature.SignerCertificate
    $actualThumbprint = $signer.Thumbprint.Replace(" ", "")
    if (-not $actualThumbprint.Equals(
        $ExpectedThumbprint,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        throw "Unexpected signer certificate for $($File.Name)."
    }
    $codeSigningEku = @(
        $signer.Extensions |
            Where-Object { $_.Oid.Value -eq "2.5.29.37" } |
            ForEach-Object { $_.EnhancedKeyUsages } |
            Where-Object { $_.Value -eq "1.3.6.1.5.5.7.3.3" }
    )
    if ($codeSigningEku.Count -eq 0) {
        throw "Signer certificate is not authorized for code signing."
    }
    Test-TrustedCertificateChain `
        -Certificate $signer `
        -Description "Signer"
    if ($null -eq $signature.TimeStamperCertificate) {
        throw "A trusted RFC3161 timestamp is required for $($File.Name)."
    }
    $timestamp = $signature.TimeStamperCertificate
    $timestampEku = @(
        $timestamp.Extensions |
            Where-Object { $_.Oid.Value -eq "2.5.29.37" } |
            ForEach-Object { $_.EnhancedKeyUsages } |
            Where-Object { $_.Value -eq "1.3.6.1.5.5.7.3.8" }
    )
    if ($timestampEku.Count -eq 0) {
        throw "Timestamp certificate does not have the time-stamping EKU."
    }
    Test-TrustedCertificateChain `
        -Certificate $timestamp `
        -Description "Timestamp"
    $fileHash = Get-FileHash -LiteralPath $File.FullName -Algorithm SHA256
    $timestampThumbprint = $timestamp.Thumbprint.Replace(" ", "")

    return [ordered]@{
        file = $File.Name
        size_bytes = $File.Length
        sha256 = $fileHash.Hash.ToLowerInvariant()
        authenticode_status = $signature.Status.ToString()
        signer_chain_trusted_at_verification = $true
        signer_subject = $signer.Subject
        signer_issuer = $signer.Issuer
        signer_thumbprint = $actualThumbprint.ToLowerInvariant()
        signer_not_before = $signer.NotBefore.ToUniversalTime().ToString("o")
        signer_not_after = $signer.NotAfter.ToUniversalTime().ToString("o")
        timestamp_present = $true
        timestamp_certificate_subject = $timestamp.Subject
        timestamp_certificate_issuer = $timestamp.Issuer
        timestamp_certificate_thumbprint =
            $timestampThumbprint.ToLowerInvariant()
        timestamp_certificate_not_before =
            $timestamp.NotBefore.ToUniversalTime().ToString("o")
        timestamp_certificate_not_after =
            $timestamp.NotAfter.ToUniversalTime().ToString("o")
        timestamp_certificate_chain_trusted_at_verification = $true
        signtool_policy_verification_exit_code = $signtoolExitCode
    }
}

function Assert-ReleaseImageLock {
    param(
        [Parameter(Mandatory = $true)]
        [IO.FileInfo]$File
    )

    $rules = [ordered]@{
        DES_POSTGRES_IMAGE = "postgres"
        DES_API_IMAGE = "ghcr.io/xiaoli2hust/datax-studio-api"
        DES_EGRESS_GUARD_IMAGE = "ghcr.io/xiaoli2hust/datax-studio-egress-guard"
        DES_WORKER_IMAGE = "ghcr.io/xiaoli2hust/datax-studio-worker"
        DES_WEB_IMAGE = "ghcr.io/xiaoli2hust/datax-studio-web"
    }
    if ($File.Length -gt 16384) {
        throw "Release image lock is too large."
    }
    $strictUtf8 = New-Object -TypeName Text.UTF8Encoding -ArgumentList $false, $true
    $text = [IO.File]::ReadAllText($File.FullName, $strictUtf8)
    if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) {
        throw "Release image lock must not contain a BOM."
    }
    $values = [ordered]@{}
    foreach ($line in ([IO.File]::ReadAllLines($File.FullName, $strictUtf8))) {
        if ($line.Length -eq 0 -or $line.StartsWith("#")) {
            continue
        }
        if ($line -ne $line.Trim()) {
            throw "Release image lock contains non-canonical whitespace."
        }
        if ($line -notmatch '^([^=]+)=(.+)$') {
            throw "Release image lock contains a malformed line."
        }
        $key = $Matches[1]
        $value = $Matches[2]
        if (-not $rules.Contains($key) -or $values.ContainsKey($key)) {
            throw "Release image lock contains an unknown or duplicate key."
        }
        $repository = [Regex]::Escape([string]$rules[$key])
        if ($value -cnotmatch "^${repository}@sha256:[0-9a-f]{64}$") {
            throw "Release image lock contains a mutable or unexpected reference."
        }
        $values[$key] = $value
    }
    if ($values.Count -ne $rules.Count) {
        throw "Release image lock is incomplete."
    }
    Write-Output -NoEnumerate $values
}

function Assert-ExactJsonProperties {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Document,
        [Parameter(Mandatory = $true)]
        [string[]]$Expected,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    [string[]]$actual = @($Document.PSObject.Properties.Name)
    if ($actual.Count -ne $Expected.Count) {
        throw "$Description has an unexpected property set."
    }
    foreach ($name in $actual) {
        if ($Expected -cnotcontains $name) {
            throw "$Description has an unexpected property set."
        }
    }
}

function Get-EvidenceRequirementsTupleComponent {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Entry,
        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $value = $Entry.evidence_requirements
    if (-not ($value -is [Array])) {
        throw "$Description evidence_requirements must be a JSON array."
    }
    [object[]]$requirements = @($value)
    if ($requirements.Count -gt 2) {
        throw "$Description contains too many evidence requirements."
    }
    $allowed = @("VERIFICATION_ORACLE_V1", "WINDOWS_E4")
    $previous = $null
    foreach ($requirement in $requirements) {
        if (-not ($requirement -is [string]) -or
            $allowed -cnotcontains $requirement -or
            ($null -ne $previous -and
                [StringComparer]::Ordinal.Compare(
                    [string]$previous,
                    [string]$requirement
                ) -ge 0)) {
            throw "$Description evidence_requirements is invalid or non-canonical."
        }
        $previous = $requirement
    }
    return "[$($requirements -join ',')]"
}

function Assert-AnonymousImagePullEvidence {
    param(
        [Parameter(Mandatory = $true)]
        [IO.FileInfo]$File,
        [Parameter(Mandatory = $true)]
        [Collections.IDictionary]$ImageLock
    )

    if ($File.Length -eq 0 -or $File.Length -gt 65536) {
        throw "Anonymous image pull evidence size is invalid."
    }
    $strictUtf8 = New-Object -TypeName Text.UTF8Encoding -ArgumentList $false, $true
    $text = [IO.File]::ReadAllText($File.FullName, $strictUtf8)
    if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) {
        throw "Anonymous image pull evidence must not contain a BOM."
    }
    $document = $text | ConvertFrom-Json
    Assert-ExactJsonProperties `
        -Document $document `
        -Expected @(
            "schema_version",
            "verification",
            "result",
            "platform",
            "docker_config_mode",
            "docker_config_sha256",
            "registry_credentials_used",
            "images"
        ) `
        -Description "Anonymous image pull evidence"
    if ($document.schema_version -cne "1.0" -or
        $document.verification -cne "ANONYMOUS_PULL_BY_DIGEST" -or
        $document.result -cne "PASS" -or
        $document.platform -cne "linux/amd64" -or
        $document.docker_config_mode -cne "EPHEMERAL_EMPTY" -or
        $document.docker_config_sha256 -cne
            "81bcbd3f950f2b31b87a64e8eca0de39db52feb0060d2bc631d7d794696604eb" -or
        $document.registry_credentials_used -ne $false) {
        throw "Anonymous image pull evidence header is invalid."
    }
    $images = @($document.images)
    $expectedKeys = @($ImageLock.Keys)
    if ($images.Count -ne $expectedKeys.Count) {
        throw "Anonymous image pull evidence does not contain five images."
    }
    for ($index = 0; $index -lt $expectedKeys.Count; $index++) {
        $entry = $images[$index]
        Assert-ExactJsonProperties `
            -Document $entry `
            -Expected @("key", "reference", "result") `
            -Description "Anonymous image pull entry"
        $key = [string]$expectedKeys[$index]
        if ($entry.key -cne $key -or
            $entry.reference -cne [string]$ImageLock[$key] -or
            $entry.result -cne "PULLED_ANONYMOUSLY") {
            throw "Anonymous image pull evidence differs from the release image lock."
        }
    }
}

function Assert-BlockedAcceptanceEvidence {
    param(
        [Parameter(Mandatory = $true)]
        [IO.FileInfo]$ManifestFile,
        [Parameter(Mandatory = $true)]
        [IO.FileInfo]$CatalogFile,
        [Parameter(Mandatory = $true)]
        [IO.FileInfo]$EnvironmentFile,
        [Parameter(Mandatory = $true)]
        [string]$Version,
        [Parameter(Mandatory = $true)]
        [string]$Commit
    )

    foreach ($item in @($ManifestFile, $CatalogFile, $EnvironmentFile)) {
        if ($item.Length -eq 0 -or $item.Length -gt 4MB) {
            throw "Acceptance evidence file size is invalid."
        }
    }
    $strictUtf8 = New-Object -TypeName Text.UTF8Encoding -ArgumentList $false, $true
    $manifestText = [IO.File]::ReadAllText($ManifestFile.FullName, $strictUtf8)
    $catalogText = [IO.File]::ReadAllText($CatalogFile.FullName, $strictUtf8)
    foreach ($text in @($manifestText, $catalogText)) {
        if ($text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) {
            throw "Acceptance evidence must not contain a BOM."
        }
    }
    $manifest = $manifestText | ConvertFrom-Json
    $catalog = $catalogText | ConvertFrom-Json
    Assert-ExactJsonProperties `
        -Document $manifest `
        -Expected @(
            "schema_version",
            "release_candidate",
            "commit_sha",
            "generated_at",
            "requirements_catalog_sha256",
            "environment_manifest_sha256",
            "coverage",
            "gate_result",
            "entries",
            "defects",
            "known_limitations"
        ) `
        -Description "Acceptance manifest"
    Assert-ExactJsonProperties `
        -Document $catalog `
        -Expected @(
            "entries",
            "entry_count",
            "post_v1_count",
            "requirement_count",
            "schema_version",
            "v1_must_count"
        ) `
        -Description "Requirements catalog"

    $expectedCandidate = "$Version-$($Commit.Substring(0, 12))"
    if ($manifest.schema_version -cne "1.1" -or
        $manifest.release_candidate -cne $expectedCandidate -or
        $manifest.commit_sha -cne $Commit -or
        $manifest.gate_result -cne "BLOCKED" -or
        $catalog.schema_version -cne "1.1") {
        throw "Acceptance evidence is not bound to this blocked candidate."
    }
    $catalogHash = (
        Get-FileHash -LiteralPath $CatalogFile.FullName -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    $environmentHash = (
        Get-FileHash -LiteralPath $EnvironmentFile.FullName -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    if ($manifest.requirements_catalog_sha256 -cne $catalogHash -or
        $manifest.environment_manifest_sha256 -cne $environmentHash) {
        throw "Acceptance evidence input hashes do not match."
    }

    $catalogEntries = @($catalog.entries)
    $manifestEntries = @($manifest.entries)
    if ($catalog.entry_count -ne $catalogEntries.Count -or
        $manifestEntries.Count -ne $catalogEntries.Count -or
        $catalog.requirement_count -lt 1 -or
        $catalog.v1_must_count -lt 1 -or
        $manifest.coverage.expected_v1_must_count -ne
            $catalog.v1_must_count -or
        $manifest.coverage.covered_v1_must_count -ne
            $catalog.v1_must_count -or
        $manifest.coverage.catalog_exact_match -ne $true -or
        @($manifest.coverage.missing_requirement_ids).Count -ne 0 -or
        @($manifest.coverage.duplicate_requirement_test_pairs).Count -ne 0) {
        throw "Acceptance evidence coverage does not match the catalog."
    }

    $expectedTuples = @{}
    foreach ($entry in $catalogEntries) {
        Assert-ExactJsonProperties `
            -Document $entry `
            -Expected @(
                "evidence_requirements",
                "minimum_evidence_level",
                "requirement_id",
                "requirement_priority",
                "test_id"
            ) `
            -Description "Requirements catalog entry"
        $evidenceRequirements = Get-EvidenceRequirementsTupleComponent `
            -Entry $entry `
            -Description "Requirements catalog entry"
        $key = @(
            $entry.requirement_id,
            $entry.requirement_priority,
            $entry.test_id,
            $entry.minimum_evidence_level,
            $evidenceRequirements
        ) -join "|"
        if ($expectedTuples.ContainsKey($key)) {
            throw "Requirements catalog contains a duplicate tuple."
        }
        $expectedTuples[$key] = $true
    }
    $actualTuples = @{}
    foreach ($entry in $manifestEntries) {
        Assert-ExactJsonProperties `
            -Document $entry `
            -Expected @(
                "requirement_id",
                "requirement_priority",
                "test_id",
                "evidence_requirements",
                "result",
                "minimum_evidence_level",
                "evidence_level",
                "oracle",
                "windows_evidence",
                "evidence",
                "executed_at",
                "environment_id"
            ) `
            -Description "Blocked acceptance entry"
        $evidenceRequirements = Get-EvidenceRequirementsTupleComponent `
            -Entry $entry `
            -Description "Blocked acceptance entry"
        $key = @(
            $entry.requirement_id,
            $entry.requirement_priority,
            $entry.test_id,
            $entry.minimum_evidence_level,
            $evidenceRequirements
        ) -join "|"
        if (-not $expectedTuples.ContainsKey($key) -or
            $actualTuples.ContainsKey($key) -or
            $entry.result -cne "NOT_RUN" -or
            $entry.evidence_level -cne "E0" -or
            $null -ne $entry.oracle -or
            $null -ne $entry.windows_evidence -or
            -not ($entry.evidence -is [Array]) -or
            $entry.evidence.Count -ne 0 -or
            $null -ne $entry.executed_at -or
            $null -ne $entry.environment_id) {
            throw "Blocked acceptance entry is invalid or overstates evidence."
        }
        $actualTuples[$key] = $true
    }
    if ($actualTuples.Count -ne $expectedTuples.Count -or
        @($manifest.defects).Count -ne 0 -or
        @($manifest.known_limitations).Count -lt 1) {
        throw "Blocked acceptance manifest is incomplete."
    }
}

$candidateItem = Get-Item -LiteralPath (
    Resolve-Path -LiteralPath $CandidateDirectory
) -Force
if (-not $candidateItem.PSIsContainer -or
    ($candidateItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw "CandidateDirectory must be a non-reparse directory."
}
$candidateRoot = [IO.Path]::GetFullPath($candidateItem.FullName)
$candidatePrefix = $candidateRoot.TrimEnd(
    [IO.Path]::DirectorySeparatorChar,
    [IO.Path]::AltDirectorySeparatorChar
) + [IO.Path]::DirectorySeparatorChar
$candidateTree = @(
    Get-ChildItem `
        -LiteralPath $candidateRoot `
        -Recurse `
        -Force `
        -ErrorAction Stop
)
foreach ($item in $candidateTree) {
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "CandidateDirectory contains a reparse-point entry."
    }
}
$setup = Resolve-RequiredFile -Path $SetupPath -Description "Setup"
$launcher = Resolve-RequiredFile -Path $LauncherPath -Description "Launcher"
$images = Resolve-RequiredFile -Path $ImagesReleaseFile -Description "Image lock"
$contextFile = Resolve-RequiredFile `
    -Path $ReleaseContextFile `
    -Description "Release context"
foreach ($item in @($setup, $launcher, $images, $contextFile)) {
    Assert-ChildOfCandidate -Item $item -RootPrefix $candidatePrefix
}
if ($setup.Name -cne "DataX-Enterprise-Studio-Setup-$ExpectedVersion-x64.exe" -or
    $launcher.Name -cne "launcher.exe" -or
    $setup.Length -eq 0 -or
    $launcher.Length -eq 0) {
    throw "Candidate executable names or sizes are invalid."
}
$imageLock = Assert-ReleaseImageLock -File $images
$anonymousPullEvidence = Resolve-RequiredFile `
    -Path (Join-Path $candidateRoot "linux-evidence\anonymous-image-pulls.json") `
    -Description "Anonymous image pull evidence"
Assert-ChildOfCandidate `
    -Item $anonymousPullEvidence `
    -RootPrefix $candidatePrefix
Assert-AnonymousImagePullEvidence `
    -File $anonymousPullEvidence `
    -ImageLock $imageLock
$acceptanceManifest = Resolve-RequiredFile `
    -Path (Join-Path $candidateRoot "linux-evidence\acceptance-manifest.json") `
    -Description "Acceptance manifest"
$requirementsCatalog = Resolve-RequiredFile `
    -Path (Join-Path $candidateRoot "linux-evidence\requirements-catalog.v1.json") `
    -Description "Requirements catalog"
$linuxReleaseContext = Resolve-RequiredFile `
    -Path (Join-Path $candidateRoot "linux-evidence\release-context.json") `
    -Description "Linux release context"
foreach ($item in @(
    $acceptanceManifest,
    $requirementsCatalog,
    $linuxReleaseContext
)) {
    Assert-ChildOfCandidate -Item $item -RootPrefix $candidatePrefix
}
Assert-BlockedAcceptanceEvidence `
    -ManifestFile $acceptanceManifest `
    -CatalogFile $requirementsCatalog `
    -EnvironmentFile $linuxReleaseContext `
    -Version $ExpectedVersion `
    -Commit $ExpectedCommit

$context = [IO.File]::ReadAllText($contextFile.FullName) | ConvertFrom-Json
if ($context.schema_version -ne "1.0" -or
    $context.artifact_kind -ne "WINDOWS_LOCAL_CANDIDATE" -or
    $context.candidate_only -ne $true -or
    $context.public_release_created -ne $false -or
    $context.repository -ne "xiaoli2hust/datax" -or
    $context.version -ne $ExpectedVersion -or
    $context.git_commit -ne $ExpectedCommit) {
    throw "Release context does not match this candidate."
}

$signtool = Resolve-RequiredCommand `
    -Name "signtool.exe" `
    -ExplicitPath $SigntoolPath
$setupSigntoolEvidence = Join-Path $candidateRoot "signtool-setup.txt"
$launcherSigntoolEvidence = Join-Path $candidateRoot "signtool-launcher.txt"
$authenticodePath = Join-Path $candidateRoot "authenticode-evidence.json"
$environmentPath = Join-Path $candidateRoot "windows-build-environment.json"
$hashManifest = Join-Path $candidateRoot "SHA256SUMS"
foreach ($path in @(
    $setupSigntoolEvidence,
    $launcherSigntoolEvidence,
    $authenticodePath,
    $environmentPath,
    $hashManifest
)) {
    if (Test-Path -LiteralPath $path) {
        throw "Candidate evidence output already exists: $path"
    }
}
$setupEvidence = Get-VerifiedSignatureEvidence `
    -File $setup `
    -ExpectedThumbprint $ExpectedSignerThumbprint `
    -Signtool $signtool `
    -SigntoolEvidencePath $setupSigntoolEvidence
$launcherEvidence = Get-VerifiedSignatureEvidence `
    -File $launcher `
    -ExpectedThumbprint $ExpectedSignerThumbprint `
    -Signtool $signtool `
    -SigntoolEvidencePath $launcherSigntoolEvidence

$authenticodeEvidence = [ordered]@{
    schema_version = "1.0"
    evidence_scope = "AUTHENTICODE_TIMESTAMP_AND_FILE_HASH_ONLY"
    candidate_only = $true
    public_release_created = $false
    version = $ExpectedVersion
    git_commit = $ExpectedCommit
    verified_at = [DateTime]::UtcNow.ToString("o")
    setup = $setupEvidence
    launcher = $launcherEvidence
    windows_installation_e2e = "NOT_RUN"
    docker_desktop_wsl2_e2e = "NOT_RUN"
    real_datax_e2e = "NOT_RUN"
}
[IO.File]::WriteAllText(
    $authenticodePath,
    ($authenticodeEvidence | ConvertTo-Json -Depth 8),
    [Text.UTF8Encoding]::new($false)
)

$windowsKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$windows = Get-ItemProperty -LiteralPath $windowsKey
if ([int]$windows.CurrentBuildNumber -lt 22000 -or
    $windows.InstallationType -ne "Client" -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture -ne
        [Runtime.InteropServices.Architecture]::X64) {
    throw "Release evidence must be generated on Windows 11 client x64."
}
$rustc = Resolve-RequiredCommand -Name "rustc.exe"
$cargo = Resolve-RequiredCommand -Name "cargo.exe"
$rustcVersion = [string](& $rustc --version)
if ($LASTEXITCODE -ne 0) {
    throw "rustc version query failed."
}
$cargoVersion = [string](& $cargo --version)
if ($LASTEXITCODE -ne 0) {
    throw "cargo version query failed."
}
$environmentEvidence = [ordered]@{
    schema_version = "1.0"
    candidate_only = $true
    captured_at = [DateTime]::UtcNow.ToString("o")
    os_product_name = [string]$windows.ProductName
    os_display_version = [string]$windows.DisplayVersion
    os_build = [string]$windows.CurrentBuildNumber
    installation_type = [string]$windows.InstallationType
    process_architecture =
        [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString()
    powershell_version = $PSVersionTable.PSVersion.ToString()
    rustc_version = $rustcVersion
    cargo_version = $cargoVersion
    authenticode_validation = "VERIFIED"
    windows_installation_e2e = "NOT_RUN"
}
[IO.File]::WriteAllText(
    $environmentPath,
    ($environmentEvidence | ConvertTo-Json -Depth 5),
    [Text.UTF8Encoding]::new($false)
)

$relativeFiles = @{}
$relativePaths = [Collections.Generic.List[string]]::new()
foreach ($item in (
    Get-ChildItem -LiteralPath $candidateRoot -File -Recurse -Force
)) {
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Candidate contains a reparse-point file."
    }
    $relative = $item.FullName.Substring($candidatePrefix.Length).Replace("\", "/")
    if ($relative -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._/-]*$' -or
        $relativeFiles.ContainsKey($relative)) {
        throw "Candidate contains a non-canonical or duplicate path."
    }
    $relativeFiles[$relative] = $item
    $relativePaths.Add($relative)
}
$relativePaths.Sort([StringComparer]::Ordinal)
$hashLines = @(
    foreach ($relative in $relativePaths) {
        $fileHash = Get-FileHash `
            -LiteralPath $relativeFiles[$relative].FullName `
            -Algorithm SHA256
        "$($fileHash.Hash.ToLowerInvariant())  $relative"
    }
)
[IO.File]::WriteAllLines(
    $hashManifest,
    $hashLines,
    [Text.UTF8Encoding]::new($false)
)
