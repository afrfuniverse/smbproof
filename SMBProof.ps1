#requires -Version 5.1
# Copyright (c) 2026 Alireza Foroughifar (@afrfuniverse, https://github.com/afrfuniverse)
# SPDX-License-Identifier: MIT

[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$Path,
    [Parameter(Mandatory)][ValidateSet('Allow', 'Deny')][string]$Expect,
    [Parameter(Mandatory)][ValidateNotNullOrEmpty()][string]$ExpectedUser,
    [ValidateNotNullOrEmpty()][string]$ExpectedSmbCredential,
    [ValidateSet('Text', 'Json')][string]$Format = 'Text',
    [ValidateNotNullOrEmpty()][string]$HtmlReport
)

Set-StrictMode -Version Latest

try {
    Import-Module (Join-Path $PSScriptRoot 'SMBProof.psm1') -ErrorAction Stop
    $probeParams = @{ Path = $Path; Expect = $Expect; ExpectedUser = $ExpectedUser }
    if ($PSBoundParameters.ContainsKey('ExpectedSmbCredential')) {
        $probeParams.ExpectedSmbCredential = $ExpectedSmbCredential
    }
    $result = Test-SmbProof @probeParams

    if ($PSBoundParameters.ContainsKey('HtmlReport')) {
        $destination = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($HtmlReport)
        $tempName = '.smbproof-' + [guid]::NewGuid().ToString('N') + '.tmp'
        $tempPath = Join-Path ([IO.Path]::GetDirectoryName($destination)) $tempName
        try {
            $html = New-SmbProofHtmlReport -Result $result
            [IO.File]::WriteAllText($tempPath, $html, [Text.UTF8Encoding]::new($false))
            [IO.File]::Move($tempPath, $destination)
        } finally {
            if ([IO.File]::Exists($tempPath)) {
                [IO.File]::Delete($tempPath)
            }
        }
    }
} catch {
    [Console]::Error.WriteLine(('SMBProof: ' + $_.Exception.Message))
    exit 2
}

if ($Format -eq 'Json') {
    $result | ConvertTo-Json -Depth 4
} else {
    $result | Format-List
}
exit $result.ExitCode
