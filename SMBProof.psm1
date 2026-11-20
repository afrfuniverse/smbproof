# Copyright (c) 2026 Alireza Foroughifar (@afrfuniverse, https://github.com/afrfuniverse)
# SPDX-License-Identifier: MIT

Set-StrictMode -Version Latest

function Split-SmbProofPath {
    param([string]$Path)

    if (-not $Path.StartsWith('\\', [StringComparison]::Ordinal)) {
        throw 'Supply the UNC path to a regular test file, such as \\fileserver\share\probe.txt.'
    }
    $parts = $Path.Substring(2).Split('\')
    if ($parts.Count -lt 3 -or $parts[0] -match '[\s\[\]]' -or $parts[1] -ieq 'IPC$') {
        throw 'A server, disk share, and test file are required.'
    }
    foreach ($part in $parts) {
        if (!$part -or $part -match '[\\/:*?"<>|\x00-\x1f]|[ .]$' -or
            $part -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)') {
            throw 'The UNC path contains an invalid or ambiguous component.'
        }
    }
    [pscustomobject]@{ Server = $parts[0]; Share = $parts[1] }
}

function Get-SmbProofWindowsUser {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $identity.Name
    } finally {
        $identity.Dispose()
    }
}

function ConvertFrom-SmbProofException {
    param([Exception]$Exception)

    while ($Exception.InnerException) {
        $Exception = $Exception.InnerException
    }
    $code = $null
    if (($Exception.HResult -band 0xffff0000) -eq 0x80070000) {
        $code = $Exception.HResult -band 0xffff
    }
    if ($code -in 5, 65) {
        return [pscustomobject]@{ Access = 'Denied'; Win32Code = $code; Detail = 'Windows returned access denied.' }
    }
    $detail = switch ($code) {
        { $_ -in 2, 3 } { 'The file or directory was not found.' }
        { $_ -in 51, 53, 64, 67, 1231 } { 'The share or network path was unavailable.' }
        { $_ -in 32, 33 } { 'A sharing or locking conflict prevented the read.' }
        { $_ -in 86, 1219, 1244, 1317, 1326, 1327, 1328, 1329, 1330, 1331, 1385, 1793, 1909 } {
            'A sign-in, account, or SMB credential conflict prevented the read.'
        }
        default { 'Windows did not return a conclusive file access result.' }
    }
    [pscustomobject]@{ Access = 'Unknown'; Win32Code = $code; Detail = $detail }
}

function Read-SmbProofTestFile {
    param([string]$Path)

    try {
        $sharing = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, $sharing)
        try {
            $null = $stream.ReadByte()
        } finally {
            $stream.Dispose()
        }
        [pscustomobject]@{ Access = 'Allowed'; Win32Code = $null; Detail = 'Opened the test file for reading and read a byte or reached end of file.' }
    } catch {
        $probe = ConvertFrom-SmbProofException -Exception $_.Exception
        if ($probe.Access -eq 'Denied') {
            # Opening a directory as a file can also return access denied.
            $attributes = $null
            try { $attributes = [IO.File]::GetAttributes($Path) } catch { }
            if ($null -ne $attributes -and ($attributes -band [IO.FileAttributes]::Directory)) {
                return [pscustomobject]@{
                    Access = 'Unknown'; Win32Code = $probe.Win32Code; Detail = 'The target is a directory. Specify the UNC path to a test file.'
                }
            }
        }
        $probe
    }
}

function Get-SmbProofCredentialEvidence {
    param([string]$Server, [string]$Share, [string]$WindowsUser)

    try {
        Get-SmbConnection -ServerName $Server -UserName $WindowsUser -ErrorAction Stop |
            Where-Object {
                $_.ServerName -ieq $Server -and $_.ShareName -ieq $Share -and
                $_.UserName -ieq $WindowsUser -and $_.Credential
            } |
            Select-Object -ExpandProperty Credential -Unique
    } catch {
        # Standard users and failed connection attempts may not have readable SMB metadata.
        return
    }
}

function Test-SmbProof {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Path,
        [Parameter(Mandatory)][ValidateSet('Allow', 'Deny')][string]$Expect,
        [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedUser,
        [ValidateNotNullOrEmpty()][string]$ExpectedSmbCredential
    )

    $target = Split-SmbProofPath -Path $Path
    $windowsUser = Get-SmbProofWindowsUser
    $requireCredential = $PSBoundParameters.ContainsKey('ExpectedSmbCredential')
    $credentialToCheck = if ($requireCredential) { $ExpectedSmbCredential } else { $ExpectedUser }

    $result = [pscustomobject][ordered]@{
        Version                = '0.1.0'
        TimestampUtc           = [datetime]::UtcNow.ToString('o')
        Status                 = 'Inconclusive'
        ExitCode               = 2
        Path                   = $Path
        ExpectedAccess         = if ($Expect -ieq 'Allow') { 'Allowed' } else { 'Denied' }
        ObservedAccess         = 'NotAttempted'
        ExpectedWindowsUser    = $ExpectedUser
        WindowsUser            = $windowsUser
        ExpectedSmbCredential  = $credentialToCheck
        RequiresSmbCredential  = $requireCredential
        ObservedSmbCredentials = @()
        SmbCredentialStatus    = 'NotChecked'
        Win32Code              = $null
        Reason                 = 'The Windows identity does not match. The file was not opened.'
    }
    if ($windowsUser -ine $ExpectedUser) {
        return $result
    }

    $probe = Read-SmbProofTestFile -Path $Path
    $result.ObservedAccess = $probe.Access
    $result.Win32Code = $probe.Win32Code
    $result.Reason = $probe.Detail
    $result.ObservedSmbCredentials = @(Get-SmbProofCredentialEvidence -Server $target.Server -Share $target.Share -WindowsUser $windowsUser)

    $result.SmbCredentialStatus = switch ($result.ObservedSmbCredentials.Count) {
        0 { 'Unavailable' }
        1 {
            if ($result.ObservedSmbCredentials[0] -ieq $credentialToCheck) { 'Matched' }
            else { 'Different' }
        }
        default { 'Ambiguous' }
    }
    switch ($result.SmbCredentialStatus) {
        'Different' { $result.Reason += ' The observed SMB credential differs from the expected credential.' }
        'Ambiguous' { $result.Reason += ' Multiple matching SMB client connections use different credentials.' }
        'Unavailable' { $result.Reason += ' The SMB credential could not be established from client metadata.' }
    }
    $credentialAcceptable = $result.SmbCredentialStatus -eq 'Matched' -or
        ($result.SmbCredentialStatus -eq 'Unavailable' -and !$requireCredential)
    if ($probe.Access -eq 'Unknown' -or !$credentialAcceptable) {
        return $result
    }

    if ($probe.Access -eq $result.ExpectedAccess) {
        $result.Status = 'Pass'
        $result.ExitCode = 0
    } else {
        $result.Status = 'Fail'
        $result.ExitCode = 1
    }
    $result
}

function New-SmbProofHtmlReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)][object]$Result)

    $rows = foreach ($field in $Result.PSObject.Properties) {
        $key = [Net.WebUtility]::HtmlEncode($field.Name)
        $value = [Net.WebUtility]::HtmlEncode(($field.Value -join ', '))
        "<tr><th scope=""row"">$key</th><td>$value</td></tr>"
    }
    $status = [Net.WebUtility]::HtmlEncode($Result.Status)
    $body = $rows -join [Environment]::NewLine
    @"
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SMBProof report</title>
<style>
body { font: 1rem/1.5 system-ui, sans-serif; background: #f2f5f8; color: #182334; margin: 0; }
main { max-width: 54rem; margin: 2rem auto; padding: 1.5rem; background: white; border: 1px solid #d9e1e9; }
h1 { margin-top: 0; font-size: 1.65rem; }
table { width: 100%; border-collapse: collapse; }
th, td { padding: .6rem; border-bottom: 1px solid #d9e1e9; text-align: left; overflow-wrap: anywhere; }
th { width: 36%; }
code { color: #17576a; }
</style>
</head>
<body><main>
<h1>SMBProof report</h1>
<p>Result <strong>$status</strong></p>
<table><caption>Read access check</caption><tbody>
$body
</tbody></table>
<p>This report records one file-read attempt. <code>Unavailable</code> SMB credential evidence does not establish the remote account.</p>
</main></body>
</html>
"@
}

Export-ModuleMember -Function Test-SmbProof, New-SmbProofHtmlReport
