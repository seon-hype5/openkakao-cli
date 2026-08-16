[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$fixtureRoot = Join-Path $repoRoot "tests\fixtures\windows-authenticode"
$sourceRoot = Join-Path $fixtureRoot "source"
$targetRoot = Join-Path $repoRoot ".target\windows-authenticode-fixture"
$buildRoot = Join-Path $targetRoot ([Guid]::NewGuid().ToString("N"))

$vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
$signTool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"

foreach ($required in @($vcvars, $signTool, (Join-Path $sourceRoot "fixture.c"), (Join-Path $sourceRoot "fixture.rc"))) {
    if (-not (Test-Path -LiteralPath $required -PathType Leaf)) {
        throw "required fixture input is unavailable"
    }
}

New-Item -ItemType Directory -Path $fixtureRoot -Force | Out-Null
New-Item -ItemType Directory -Path $buildRoot -Force | Out-Null

function Get-FileSha256([string]$Path) {
    (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Get-BytesSha256([byte[]]$Bytes) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Get-DerLength([int]$Length) {
    if ($Length -lt 0) {
        throw "negative DER length"
    }
    if ($Length -lt 128) {
        return [byte[]]@([byte]$Length)
    }
    $encoded = [System.Collections.Generic.List[byte]]::new()
    $remaining = $Length
    while ($remaining -gt 0) {
        $encoded.Insert(0, [byte]($remaining -band 0xff))
        $remaining = $remaining -shr 8
    }
    $result = [System.Collections.Generic.List[byte]]::new()
    $result.Add([byte](0x80 -bor $encoded.Count))
    $result.AddRange($encoded)
    $result.ToArray()
}

function New-DerValue([byte]$Tag, [byte[]]$Value) {
    $result = [System.Collections.Generic.List[byte]]::new()
    $result.Add($Tag)
    [byte[]]$encodedLength = @(Get-DerLength $Value.Length)
    $result.AddRange($encodedLength)
    $result.AddRange($Value)
    $result.ToArray()
}

function Get-RsaSpki([System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate) {
    if ($Certificate.PublicKey.Oid.Value -ne "1.2.840.113549.1.1.1") {
        throw "fixture certificate must use RSA"
    }
    [byte[]]$rsaOid = 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01
    [byte[]]$parameters = $Certificate.PublicKey.EncodedParameters.RawData
    [byte[]]$algorithmValue = $rsaOid + $parameters
    [byte[]]$algorithm = New-DerValue 0x30 $algorithmValue
    [byte[]]$keyValue = $Certificate.PublicKey.EncodedKeyValue.RawData
    [byte[]]$bitStringValue = [byte[]]@(0) + $keyValue
    [byte[]]$bitString = New-DerValue 0x03 $bitStringValue
    New-DerValue 0x30 ([byte[]]($algorithm + $bitString))
}

# Import the reviewed MSVC environment into this PowerShell process without
# creating a child build project or modifying machine state.
$environmentLines = & $env:ComSpec /d /s /c "call `"$vcvars`" >nul && set"
if ($LASTEXITCODE -ne 0) {
    throw "MSVC environment initialization failed"
}
foreach ($line in $environmentLines) {
    $separator = $line.IndexOf("=")
    if ($separator -gt 0) {
        $name = $line.Substring(0, $separator)
        $value = $line.Substring($separator + 1)
        Set-Item -LiteralPath "Env:$name" -Value $value
    }
}

$compiler = (Get-Command cl.exe -ErrorAction Stop).Source
$linker = (Get-Command link.exe -ErrorAction Stop).Source
$resourceCompiler = (Get-Command rc.exe -ErrorAction Stop).Source
$object = Join-Path $buildRoot "fixture.obj"
$resource = Join-Path $buildRoot "fixture.res"
$unsigned = Join-Path $buildRoot "fixture-unsigned.exe"
$signed = Join-Path $buildRoot "fixture.exe"
$pfx = Join-Path $buildRoot "fixture-private.pfx"
$password = "OPENKAKAO_SYNTHETIC_FIXTURE_ONLY"

& $resourceCompiler /nologo "/fo$resource" (Join-Path $sourceRoot "fixture.rc")
if ($LASTEXITCODE -ne 0) {
    throw "fixture resource compilation failed"
}

& $compiler /nologo /O1 /GS /guard:cf /MT /DUNICODE /D_UNICODE "/Fo$object" `
    (Join-Path $sourceRoot "fixture.c") $resource "/Fe$unsigned" /link `
    /SUBSYSTEM:WINDOWS /DYNAMICBASE /NXCOMPAT /GUARD:CF /OPT:REF /OPT:ICF
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $unsigned -PathType Leaf)) {
    throw "fixture compilation failed"
}

$unsignedSha256 = Get-FileSha256 $unsigned
Copy-Item -LiteralPath $unsigned -Destination $signed

$rsa = [System.Security.Cryptography.RSACng]::new(2048)
$certificate = $null
$pfxBytes = $null
try {
    $subject = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new(
        "CN=OPENKAKAO_SYNTHETIC_FIXTURE_ONLY"
    )
    $request = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
        $subject,
        $rsa,
        [System.Security.Cryptography.HashAlgorithmName]::SHA256,
        [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
    )
    $eku = [System.Security.Cryptography.OidCollection]::new()
    $eku.Add([System.Security.Cryptography.Oid]::new("1.3.6.1.5.5.7.3.3")) | Out-Null
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($eku, $true)
    )
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true)
    )
    $request.CertificateExtensions.Add(
        [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new(
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature,
            $true
        )
    )
    $certificate = $request.CreateSelfSigned(
        [DateTimeOffset]::new(2025, 1, 1, 0, 0, 0, [TimeSpan]::Zero),
        [DateTimeOffset]::new(2035, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
    )
    $pfxBytes = $certificate.Export(
        [System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx,
        $password
    )
    [System.IO.File]::WriteAllBytes($pfx, $pfxBytes)

    & $signTool sign /fd SHA256 /f $pfx /p $password `
        /d OPENKAKAO_SYNTHETIC_FIXTURE_ONLY $signed
    if ($LASTEXITCODE -ne 0) {
        throw "fixture signing failed"
    }

    $signature = Get-AuthenticodeSignature -LiteralPath $signed
    if ($null -eq $signature.SignerCertificate -or $signature.Status -eq "NotSigned" -or $signature.Status -eq "HashMismatch") {
        throw "fixture embedded signature validation failed"
    }
    if ($null -ne $signature.TimeStamperCertificate) {
        throw "fixture must not carry a timestamp"
    }

    [byte[]]$certificateDer = $certificate.Export(
        [System.Security.Cryptography.X509Certificates.X509ContentType]::Cert
    )
    [byte[]]$spkiDer = Get-RsaSpki $certificate
    $fixtureSha256 = Get-FileSha256 $signed
    $certificateSha256 = Get-BytesSha256 $certificateDer
    $spkiSha256 = Get-BytesSha256 $spkiDer
    if ((Get-BytesSha256 $signature.SignerCertificate.RawData) -ne $certificateSha256) {
        throw "embedded signer does not match the generated fixture certificate"
    }

    Copy-Item -LiteralPath $signed -Destination (Join-Path $fixtureRoot "fixture.exe") -Force
    [System.IO.File]::WriteAllBytes((Join-Path $fixtureRoot "signer.cer"), $certificateDer)

    $utf8 = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllText(
        (Join-Path $fixtureRoot "fixture.exe.sha256"),
        "$fixtureSha256  fixture.exe`n",
        $utf8
    )
    $compilerVersion = (Get-Item -LiteralPath $compiler).VersionInfo.FileVersion
    $signToolVersion = (Get-Item -LiteralPath $signTool).VersionInfo.FileVersion
    $manifest = @"
schema_version = 1
fixture_file = "fixture.exe"
fixture_sha256 = "$fixtureSha256"
unsigned_sha256 = "$unsignedSha256"
certificate_file = "signer.cer"
certificate_sha256 = "$certificateSha256"
leaf_spki_sha256 = "$spkiSha256"
build_script_sha256 = "$(Get-FileSha256 $PSCommandPath)"
source_c_sha256 = "$(Get-FileSha256 (Join-Path $sourceRoot "fixture.c"))"
source_rc_sha256 = "$(Get-FileSha256 (Join-Path $sourceRoot "fixture.rc"))"
signature_count = 1
timestamped = false
certificate_subject = "OPENKAKAO_SYNTHETIC_FIXTURE_ONLY"
certificate_not_before_utc = "2025-01-01T00:00:00Z"
certificate_not_after_utc = "2035-01-01T00:00:00Z"
private_key_retention = "not_retained_after_signing"
compiler_file_version = "$compilerVersion"
linker_file_version = "$((Get-Item -LiteralPath $linker).VersionInfo.FileVersion)"
resource_compiler_file_version = "$((Get-Item -LiteralPath $resourceCompiler).VersionInfo.FileVersion)"
signtool_file_version = "$signToolVersion"
windows_sdk = "10.0.26100.0"
"@
    [System.IO.File]::WriteAllText(
        (Join-Path $fixtureRoot "build-manifest.toml"),
        $manifest,
        $utf8
    )
}
finally {
    if ($null -ne $pfxBytes) {
        [Array]::Clear($pfxBytes, 0, $pfxBytes.Length)
    }
    if (Test-Path -LiteralPath $pfx -PathType Leaf) {
        Remove-Item -LiteralPath $pfx -Force
    }
    if ($null -ne $certificate) {
        $certificate.Dispose()
    }
    $rsa.Dispose()
}

Write-Output "synthetic Authenticode fixture generated"
