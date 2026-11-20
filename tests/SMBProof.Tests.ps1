#requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$root = Split-Path -Parent $PSScriptRoot
$module = Import-Module (Join-Path $root 'SMBProof.psm1') -Force -PassThru
$script:passed = 0
$target = '\\fileserver.example.test\Backups$\Test\probe.txt'

function Assert-Equal {
    param($Value, $Expected)
    if ($Value -cne $Expected) {
        throw "Expected [$Expected], received [$Value]."
    }
}

function Invoke-Test {
    param([string]$Name, [scriptblock]$Test)
    try { & $Test } catch { throw "$Name failed. $($_.Exception.Message)" }
    $script:passed++
    Write-Host "PASS $Name"
}

function Set-ProbeFixture {
    param(
        [string]$Access,
        [string[]]$Credentials = @(),
        [string]$WindowsUser = 'LAB\tester'
    )
    & $module {
        param($Access, $Credentials, $WindowsUser)
        $script:fixtureAccess = $Access
        $script:fixtureCredentials = $Credentials
        $script:fixtureUser = $WindowsUser
        $script:probeCalls = 0
        $script:credentialCalls = 0
        function script:Get-SmbProofWindowsUser { $script:fixtureUser }
        function script:Read-SmbProofTestFile {
            param([string]$Path)
            if ($Path -cne '\\fileserver.example.test\Backups$\Test\probe.txt') {
                throw 'The probe path changed.'
            }
            $script:probeCalls++
            [pscustomobject]@{ Access = $script:fixtureAccess; Win32Code = $null; Detail = 'Fixture result.' }
        }
        function script:Get-SmbProofCredentialEvidence {
            param([string]$Server, [string]$Share, [string]$WindowsUser)
            if ($Server -cne 'fileserver.example.test' -or $Share -cne 'Backups$' -or $WindowsUser -cne $script:fixtureUser) {
                throw 'The query was not scoped to the tested identity and share.'
            }
            $script:credentialCalls++
            $script:fixtureCredentials
        }
    } $Access $Credentials $WindowsUser
}

$scratch = Join-Path ([IO.Path]::GetTempPath()) ('smbproof-tests-' + [guid]::NewGuid().ToString('N'))
$null = [IO.Directory]::CreateDirectory($scratch)
$file = Join-Path $scratch 'test-file.txt'
$report = Join-Path $scratch 'report.html'
try {
    [IO.File]::WriteAllText($file, 'fixture contents')

    Invoke-Test 'parses hidden share and nested test file' {
        $parsed = & $module { Split-SmbProofPath -Path $args[0] } $target
        Assert-Equal $parsed.Server 'fileserver.example.test'
        Assert-Equal $parsed.Share 'Backups$'
    }
    Invoke-Test 'rejects malformed UNC paths, streams, and device namespaces' {
        foreach ($path in 'C:\a.txt', '\\server\share', '\\.\PIPE\abc', '\\server\IPC$\abc',
            '\\server\share\..\probe.txt', '\\server\share\foo*', '\\server\share\a.txt:stream',
            '\\server\share\NUL.txt', '\\server\share\folder\', '\\?\UNC\server\share\a.txt') {
            $rejected = $false
            try { $null = & $module { Split-SmbProofPath -Path $args[0] } $path } catch { $rejected = $true }
            Assert-Equal $rejected $true
        }
    }
    Invoke-Test 'reads a local fixture through the Windows file API' {
        $read = & $module { Read-SmbProofTestFile -Path $args[0] } $file
        Assert-Equal $read.Access 'Allowed'
        Assert-Equal ([IO.File]::ReadAllText($file)) 'fixture contents'
        if ($read.Detail.Contains('fixture contents')) { throw 'The probe captured file contents.' }
    }
    Invoke-Test 'a missing file is inconclusive' {
        $read = & $module { Read-SmbProofTestFile -Path $args[0] } (Join-Path $scratch 'missing.txt')
        Assert-Equal $read.Access 'Unknown'
        Assert-Equal $read.Win32Code 2
    }
    Invoke-Test 'a directory is never treated as an access-denied file' {
        $read = & $module { Read-SmbProofTestFile -Path $args[0] } $scratch
        Assert-Equal $read.Access 'Unknown'
    }
    Invoke-Test 'a file-sharing conflict is inconclusive' {
        $held = [IO.File]::Open($file, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
        try { $read = & $module { Read-SmbProofTestFile -Path $args[0] } $file }
        finally { $held.Dispose() }
        Assert-Equal $read.Access 'Unknown'
        Assert-Equal $read.Win32Code 32
    }
    Invoke-Test 'separates access denied from authentication and network errors' {
        foreach ($code in 5, 65, 53, 67, 1219, 1326, 1385) {
            $exception = [IO.IOException]::new('Synthetic fault', [int](-2147024896 + $code))
            $wrapped = [Exception]::new('Wrapper', $exception)
            $read = & $module { ConvertFrom-SmbProofException -Exception $args[0] } $wrapped
            $expected = if ($code -in 5, 65) { 'Denied' } else { 'Unknown' }
            Assert-Equal $read.Access $expected
            Assert-Equal $read.Win32Code $code
        }
    }
    Invoke-Test 'the wrong Windows identity never opens the file' {
        Set-ProbeFixture -Access Allowed -WindowsUser 'LAB\other'
        $result = Test-SmbProof -Path $target -ExpectedUser 'LAB\tester' -Expect Deny
        Assert-Equal $result.Status 'Inconclusive'
        Assert-Equal $result.ObservedAccess 'NotAttempted'
        Assert-Equal (& $module { $script:probeCalls + $script:credentialCalls }) 0
    }
    Invoke-Test 'expected access matches and an unexpected read fails' {
        Set-ProbeFixture -Access Allowed -Credentials 'lab\tester'
        $result = Test-SmbProof -Path $target -ExpectedUser 'LAB\tester' -Expect Allow
        Assert-Equal $result.Status 'Pass'
        Assert-Equal $result.ExitCode 0
        Assert-Equal $result.SmbCredentialStatus 'Matched'
        $result = Test-SmbProof -Path $target -ExpectedUser 'LAB\tester' -Expect Deny
        Assert-Equal $result.Status 'Fail'
        Assert-Equal $result.ExitCode 1
    }
    Invoke-Test 'an observed denial satisfies a deny expectation' {
        Set-ProbeFixture -Access Denied -Credentials 'LAB\tester'
        $result = Test-SmbProof -Path $target -ExpectedUser 'LAB\tester' -Expect Deny
        Assert-Equal $result.Status 'Pass'
        Assert-Equal $result.ObservedAccess 'Denied'
    }
    Invoke-Test 'an unavailable credential is reported and an explicit credential is required' {
        Set-ProbeFixture -Access Denied
        $result = Test-SmbProof -Path $target -ExpectedUser 'LAB\tester' -Expect Deny
        Assert-Equal $result.SmbCredentialStatus 'Unavailable'
        Assert-Equal $result.Status 'Pass'
        $result = Test-SmbProof -Path $target -ExpectedUser 'LAB\tester' -Expect Deny -ExpectedSmbCredential 'LAB\tester'
        Assert-Equal $result.Status 'Inconclusive'
        Assert-Equal $result.ExitCode 2
    }
    Invoke-Test 'detects a different SMB credential and supports an explicit expected credential' {
        Set-ProbeFixture -Access Allowed -Credentials 'LAB\service-user'
        $result = Test-SmbProof -Path $target -ExpectedUser 'LAB\tester' -Expect Allow
        Assert-Equal $result.SmbCredentialStatus 'Different'
        Assert-Equal $result.Status 'Inconclusive'
        $result = Test-SmbProof -Path $target -ExpectedUser 'LAB\tester' -Expect Allow -ExpectedSmbCredential 'LAB\service-user'
        Assert-Equal $result.Status 'Pass'
    }
    Invoke-Test 'multiple SMB credentials keep the decision inconclusive' {
        Set-ProbeFixture -Access Allowed -Credentials @('LAB\tester', 'LAB\service-user')
        $result = Test-SmbProof -Path $target -ExpectedUser 'LAB\tester' -Expect Allow
        Assert-Equal $result.SmbCredentialStatus 'Ambiguous'
        Assert-Equal $result.Status 'Inconclusive'
    }
    Invoke-Test 'an inconclusive file result never satisfies an expected denial' {
        Set-ProbeFixture -Access Unknown -Credentials 'LAB\tester'
        $result = Test-SmbProof -Path $target -ExpectedUser 'LAB\tester' -Expect Deny
        Assert-Equal $result.Status 'Inconclusive'
        Assert-Equal $result.ExitCode 2
    }
    Invoke-Test 'the HTML report escapes input and uses no external resources' {
        $html = New-SmbProofHtmlReport -Result ([pscustomobject]@{ Status = 'Pass'; Path = '<script>alert("test")</script>' })
        if ($html -match '<script>|<link\s+href=|href="https?://') { throw 'Unexpected active or external content.' }
        if ($html -notmatch '&lt;script&gt;') { throw 'Escaped evidence was missing.' }
    }
    Invoke-Test 'the CLI returns JSON and exit code 2 and preserves existing HTML reports' {
        $exe = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'powershell.exe' } else { 'pwsh.exe' }
        $powershell = Join-Path $PSHOME $exe
        $cli = Join-Path $root 'SMBProof.ps1'
        $invocation = @('-NoProfile', '-NonInteractive', '-File', $cli, '-Path', $target, '-Expect', 'Deny',
            '-ExpectedUser', 'FIXTURE\not-the-running-user', '-Format', 'Json', '-HtmlReport', $report)
        $json = & $powershell @invocation
        Assert-Equal $LASTEXITCODE 2
        Assert-Equal (($json -join [Environment]::NewLine) | ConvertFrom-Json).ObservedAccess 'NotAttempted'
        $saved = [IO.File]::ReadAllText($report)
        if ($saved -notmatch '<!doctype html>') { throw 'No complete HTML report was saved.' }
        $p = [Diagnostics.ProcessStartInfo]::new()
        $p.FileName = $powershell
        $p.Arguments = ($invocation | ForEach-Object { '"' + $_ + '"' }) -join ' '
        $p.UseShellExecute = $false
        $p.RedirectStandardError = $true
        $child = [Diagnostics.Process]::Start($p)
        try {
            $diagnostic = $child.StandardError.ReadToEnd()
            $child.WaitForExit()
            Assert-Equal $child.ExitCode 2
            if ($diagnostic -notmatch 'SMBProof') { throw 'No overwrite error was reported.' }
        } finally { $child.Dispose() }
        Assert-Equal ([IO.File]::ReadAllText($report)) $saved
    }
} finally {
    [IO.File]::Delete($file)
    [IO.File]::Delete($report)
    [IO.Directory]::Delete($scratch)
}

Write-Host "$script:passed tests passed."
