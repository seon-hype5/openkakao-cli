[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if ($env:OS -ne "Windows_NT") {
    throw "Windows is required"
}

if (-not ("OpenKakao.NativeQualification" -as [type])) {
    $nativeSource = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

namespace OpenKakao
{
    [StructLayout(LayoutKind.Sequential)]
    public struct StrongSignPara
    {
        public UInt32 cbSize;
        public UInt32 dwInfoChoice;
        public IntPtr pszOID;
    }

    public static class NativeQualification
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true,
            EntryPoint = "QueryFullProcessImageNameW")]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool QueryFullProcessImageName(
            IntPtr process,
            UInt32 flags,
            StringBuilder path,
            ref UInt32 size);

        [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CertIsStrongHashToSign(
            ref StrongSignPara strongSignPara,
            string hashAlgorithm,
            IntPtr signingCertificate);
    }
}
'@
    Add-Type -TypeDefinition $nativeSource -Language CSharp
}

function Get-ExactProcessImagePath {
    param([Parameter(Mandatory = $true)][System.Diagnostics.Process]$Process)

    $buffer = [System.Text.StringBuilder]::new(32768)
    [uint32]$length = $buffer.Capacity
    $ok = [OpenKakao.NativeQualification]::QueryFullProcessImageName(
        $Process.Handle,
        0,
        $buffer,
        [ref]$length)
    if (-not $ok -or $length -eq 0 -or $length -ge $buffer.Capacity) {
        throw "process image path query failed"
    }
    return [System.IO.Path]::GetFullPath($buffer.ToString())
}

function Assert-ExactPath {
    param(
        [Parameter(Mandatory = $true)][string]$Observed,
        [Parameter(Mandatory = $true)][string]$Expected
    )

    $observedFull = [System.IO.Path]::GetFullPath($Observed)
    $expectedFull = [System.IO.Path]::GetFullPath($Expected)
    if (-not $observedFull.Equals(
        $expectedFull,
        [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "process image path did not match the qualified timing"
    }
}

function Start-SyntheticImageProcess {
    param(
        [Parameter(Mandatory = $true)][string]$CaseRoot,
        [Parameter(Mandatory = $true)][string]$SystemHelper
    )

    [System.IO.Directory]::CreateDirectory($CaseRoot) | Out-Null
    $sourcePath = Join-Path $CaseRoot "running.exe"
    $renamedPath = Join-Path $CaseRoot "running-renamed.exe"
    [System.IO.File]::Copy($SystemHelper, $sourcePath, $false)
    $sourceHash = (Get-FileHash -LiteralPath $SystemHelper -Algorithm SHA256).Hash
    $copyHash = (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash
    if (-not $sourceHash.Equals(
        $copyHash,
        [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "synthetic helper copy did not preserve the system bytes"
    }

    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $sourcePath
    $start.Arguments = "-n 30 -w 1000 127.0.0.1"
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $start
    if (-not $process.Start()) {
        throw "synthetic image helper did not start"
    }
    Start-Sleep -Milliseconds 100
    if ($process.HasExited) {
        $process.Dispose()
        throw "synthetic image helper exited before qualification"
    }

    return [pscustomobject]@{
        Process = $process
        SourcePath = $sourcePath
        RenamedPath = $renamedPath
    }
}

function Stop-SyntheticImageProcess {
    param([Parameter(Mandatory = $true)]$Fixture)

    try {
        if (-not $Fixture.Process.HasExited) {
            $Fixture.Process.Kill()
            if (-not $Fixture.Process.WaitForExit(5000)) {
                throw "synthetic image helper did not stop"
            }
        }
    }
    finally {
        $Fixture.Process.Dispose()
    }
}

function Replace-SyntheticImage {
    param([Parameter(Mandatory = $true)]$Fixture)

    [System.IO.File]::Move($Fixture.SourcePath, $Fixture.RenamedPath)
    $replacement = [System.Text.Encoding]::ASCII.GetBytes(
        "OPENKAKAO_SYNTHETIC_REPLACEMENT_V1")
    [System.IO.File]::WriteAllBytes($Fixture.SourcePath, $replacement)
    [Array]::Clear($replacement, 0, $replacement.Length)
}

$temporaryBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$temporaryPrefix = $temporaryBase.TrimEnd(
    [System.IO.Path]::DirectorySeparatorChar,
    [System.IO.Path]::AltDirectorySeparatorChar) +
    [System.IO.Path]::DirectorySeparatorChar
$qualificationRoot = [System.IO.Path]::GetFullPath((Join-Path $temporaryBase (
    "openkakao-native-qualification-" + [guid]::NewGuid().ToString("N"))))
if (-not $qualificationRoot.StartsWith(
    $temporaryPrefix,
    [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "synthetic qualification root escaped the temporary directory"
}

$oidPointer = [IntPtr]::Zero
$activeFixture = $null
try {
    [System.IO.Directory]::CreateDirectory($qualificationRoot) | Out-Null
    $driveRoot = [System.IO.Path]::GetPathRoot($qualificationRoot)
    $fileSystem = ([System.IO.DriveInfo]::new($driveRoot)).DriveFormat
    if (-not $fileSystem.Equals("NTFS", [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "qualification requires NTFS"
    }

    $oidPointer = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi(
        "1.3.6.1.4.1.311.72.1.1")
    $strongPolicy = [OpenKakao.StrongSignPara]::new()
    $strongPolicy.cbSize = [uint32][System.Runtime.InteropServices.Marshal]::SizeOf(
        $strongPolicy)
    $strongPolicy.dwInfoChoice = 2
    $strongPolicy.pszOID = $oidPointer
    $md5Allowed = [OpenKakao.NativeQualification]::CertIsStrongHashToSign(
        [ref]$strongPolicy,
        "MD5",
        [IntPtr]::Zero)
    $sha1Allowed = [OpenKakao.NativeQualification]::CertIsStrongHashToSign(
        [ref]$strongPolicy,
        "SHA1",
        [IntPtr]::Zero)
    $sha256Allowed = [OpenKakao.NativeQualification]::CertIsStrongHashToSign(
        [ref]$strongPolicy,
        "SHA256",
        [IntPtr]::Zero)
    if ($md5Allowed -or $sha1Allowed -or -not $sha256Allowed) {
        throw "OS strong-sign hash semantics did not match SHA-2-only policy"
    }

    $systemHelper = Join-Path ([System.Environment]::SystemDirectory) "ping.exe"
    if (-not [System.IO.File]::Exists($systemHelper)) {
        throw "Windows loopback helper was unavailable"
    }

    # Replacement completed before the first query. The process query must
    # report the renamed backing image rather than the new file at the old path.
    $activeFixture = Start-SyntheticImageProcess `
        -CaseRoot (Join-Path $qualificationRoot "before") `
        -SystemHelper $systemHelper
    Replace-SyntheticImage -Fixture $activeFixture
    Assert-ExactPath `
        -Observed (Get-ExactProcessImagePath -Process $activeFixture.Process) `
        -Expected $activeFixture.RenamedPath
    Stop-SyntheticImageProcess -Fixture $activeFixture
    $activeFixture = $null

    # Replacement between the first and second queries must change the path.
    $activeFixture = Start-SyntheticImageProcess `
        -CaseRoot (Join-Path $qualificationRoot "between") `
        -SystemHelper $systemHelper
    $firstPath = Get-ExactProcessImagePath -Process $activeFixture.Process
    Assert-ExactPath -Observed $firstPath -Expected $activeFixture.SourcePath
    Replace-SyntheticImage -Fixture $activeFixture
    $secondPath = Get-ExactProcessImagePath -Process $activeFixture.Process
    Assert-ExactPath -Observed $secondPath -Expected $activeFixture.RenamedPath
    if ($firstPath.Equals($secondPath, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "process image requery remained stale after replacement"
    }
    Stop-SyntheticImageProcess -Fixture $activeFixture
    $activeFixture = $null

    # After both queries, a read-only handle without write/delete sharing must
    # deny rename until the guard closes.
    $activeFixture = Start-SyntheticImageProcess `
        -CaseRoot (Join-Path $qualificationRoot "after") `
        -SystemHelper $systemHelper
    $firstPath = Get-ExactProcessImagePath -Process $activeFixture.Process
    Assert-ExactPath -Observed $firstPath -Expected $activeFixture.SourcePath
    $guard = [System.IO.File]::Open(
        $activeFixture.SourcePath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read)
    try {
        $secondPath = Get-ExactProcessImagePath -Process $activeFixture.Process
        Assert-ExactPath -Observed $secondPath -Expected $activeFixture.SourcePath
        $renameBlocked = $false
        try {
            [System.IO.File]::Move(
                $activeFixture.SourcePath,
                $activeFixture.RenamedPath)
        }
        catch [System.IO.IOException] {
            $renameBlocked = $true
        }
        catch [System.UnauthorizedAccessException] {
            $renameBlocked = $true
        }
        if (-not $renameBlocked) {
            throw "guarded candidate unexpectedly allowed rename"
        }
    }
    finally {
        $guard.Dispose()
    }
    Replace-SyntheticImage -Fixture $activeFixture
    Stop-SyntheticImageProcess -Fixture $activeFixture
    $activeFixture = $null

    Write-Output ((
        "windows_version={0} filesystem=NTFS strong_hash=md5:false,sha1:false,sha256:true " +
        "process_image_timings=before:pass,between:pass,after:pass") -f
        [System.Environment]::OSVersion.Version.ToString())
}
finally {
    try {
        if ($null -ne $activeFixture) {
            Stop-SyntheticImageProcess -Fixture $activeFixture
        }
    }
    finally {
        if ($oidPointer -ne [IntPtr]::Zero) {
            [System.Runtime.InteropServices.Marshal]::FreeHGlobal($oidPointer)
        }
        if ([System.IO.Directory]::Exists($qualificationRoot)) {
            $resolvedCleanup = [System.IO.Path]::GetFullPath($qualificationRoot)
            if (-not $resolvedCleanup.StartsWith(
                $temporaryPrefix,
                [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "refused unsafe synthetic cleanup target"
            }
            [System.IO.Directory]::Delete($resolvedCleanup, $true)
        }
    }
}
