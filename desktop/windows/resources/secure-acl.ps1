[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$TargetPath,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^S-1-(?:[0-9]+-)+[0-9]+$')]
    [string]$UserSid,
    [Parameter(Mandatory = $true)]
    [ValidateSet("Directory", "File")]
    [string]$Kind
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($TargetPath -notmatch '^[A-Za-z]:\\' -or $TargetPath.StartsWith('\\')) {
    throw "Only an absolute local drive path is allowed."
}

$item = Get-Item -LiteralPath $TargetPath -Force
if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Reparse points are not allowed."
}
if ($Kind -eq "Directory" -and -not $item.PSIsContainer) {
    throw "Expected a directory."
}
if ($Kind -eq "File" -and $item.PSIsContainer) {
    throw "Expected a file."
}

$user = New-Object -TypeName Security.Principal.SecurityIdentifier -ArgumentList $UserSid
$system = New-Object -TypeName Security.Principal.SecurityIdentifier -ArgumentList "S-1-5-18"
$allow = [Security.AccessControl.AccessControlType]::Allow
$full = [Security.AccessControl.FileSystemRights]::FullControl

if ($Kind -eq "Directory") {
    $acl = New-Object -TypeName Security.AccessControl.DirectorySecurity
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit `
        -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagation = [Security.AccessControl.PropagationFlags]::None
    $userRule = New-Object -TypeName Security.AccessControl.FileSystemAccessRule `
        -ArgumentList $user, $full, $inheritance, $propagation, $allow
    $systemRule = New-Object -TypeName Security.AccessControl.FileSystemAccessRule `
        -ArgumentList $system, $full, $inheritance, $propagation, $allow
}
else {
    $acl = New-Object -TypeName Security.AccessControl.FileSecurity
    $userRule = New-Object -TypeName Security.AccessControl.FileSystemAccessRule `
        -ArgumentList $user, $full, $allow
    $systemRule = New-Object -TypeName Security.AccessControl.FileSystemAccessRule `
        -ArgumentList $system, $full, $allow
}

$acl.AddAccessRule($userRule)
$acl.AddAccessRule($systemRule)
$acl.SetOwner($user)
$acl.SetAccessRuleProtection($true, $false)
Set-Acl -LiteralPath $TargetPath -AclObject $acl

$verified = Get-Acl -LiteralPath $TargetPath
if (-not $verified.AreAccessRulesProtected) {
    throw "DACL inheritance remains enabled."
}
if ($verified.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $UserSid) {
    throw "Unexpected owner."
}

$rules = @($verified.GetAccessRules(
    $true,
    $false,
    [Security.Principal.SecurityIdentifier]
))
if ($rules.Count -ne 2) {
    throw "Unexpected explicit ACE count."
}

$seen = @{}
foreach ($rule in $rules) {
    $sid = $rule.IdentityReference.Value
    if ($rule.IsInherited -or $rule.AccessControlType -ne $allow) {
        throw "Inherited or deny ACE found."
    }
    if (($rule.FileSystemRights -band $full) -ne $full) {
        throw "ACE does not grant exactly the required full-control baseline."
    }
    if ($Kind -eq "Directory") {
        $requiredInheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit `
            -bor [Security.AccessControl.InheritanceFlags]::ObjectInherit
        if ($rule.InheritanceFlags -ne $requiredInheritance -or
            $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
            throw "Directory ACE inheritance flags are not exact."
        }
    }
    elseif ($rule.InheritanceFlags -ne [Security.AccessControl.InheritanceFlags]::None -or
        $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) {
        throw "File ACE inheritance flags are not exact."
    }
    if ($sid -ne $UserSid -and $sid -ne "S-1-5-18") {
        throw "Unexpected principal found in DACL."
    }
    if ($seen.ContainsKey($sid)) {
        throw "Duplicate principal ACE found."
    }
    $seen[$sid] = $true
}
if (-not $seen.ContainsKey($UserSid) -or -not $seen.ContainsKey("S-1-5-18")) {
    throw "Required ACE is missing."
}
