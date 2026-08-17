[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("Default", "Override")]
    [string]$InstallMode
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$expectedRepository = "seon-hype5/openkakao-cli"
# The corporate-page lk alias rejects hosted-runner traffic. This app-pc alias
# is the byte-identical URL pinned by the reviewed Microsoft winget manifest.
$installerUri = "https://app-pc.kakaocdn.net/talk/win32/x64/KakaoTalk_Setup.exe"
$installerLength = [int64]94763296
$installerSha256 = "57dc1e9aaa56df4354b5bbf4daa60728375b08b834434777c28e60888e821882"
$sevenZipUri = "https://github.com/ip7z/7zip/releases/download/26.02/7z2602-x64.msi"
$sevenZipLength = [int64]1999872
$sevenZipSha256 = "db407a4f6d4999e5c7bc00ce8a882be94717b56e7fa68140fe3f12605d91643e"
$targetLength = [int64]34857576
$targetSha256 = "882b326ad348ed9d51b92fcf3aa09ada27ed4a737fba4b8ab4d7168576c96e50"
$targetSpkiSha256 = "c7a395989045de47835902e0e9123a4d5dfa7f2efef6ec9cb036aedc697886dc"
$targetAuthenticodeSha384 = "0495b8cf2382be66049fe8dab14bc47cbc6c72718979dd4111e7e28c386dcf347647679d185883f74c98ffc02917adc7"
$targetVersion = "26.7.0.5255"
$targetMachine = [uint16]0x8664
$targetDigestOid = "2.16.840.1.101.3.4.2.2"
$rsaEncryptionOid = "1.2.840.113549.1.1.1"
$nestedSignatureOid = "1.3.6.1.4.1.311.2.4.1"

if ($env:OS -ne "Windows_NT") {
    throw "Windows is required"
}
if ($env:GITHUB_ACTIONS -ne "true" -or $env:GITHUB_REPOSITORY -ne $expectedRepository) {
    throw "this qualification may run only in the reviewed fork GitHub Actions environment"
}
if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    throw "RUNNER_TEMP is required"
}

function Get-LowerHex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    return [Convert]::ToHexString($Bytes).ToLowerInvariant()
}

function Assert-PinnedFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][int64]$Length,
        [Parameter(Mandatory = $true)][string]$Sha256,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $item = Get-Item -LiteralPath $Path
    if ($item.Length -ne $Length) {
        throw "$Label byte length did not match the reviewed value"
    }
    $observed = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    if (-not $observed.Equals($Sha256, [StringComparison]::Ordinal)) {
        throw "$Label SHA-256 did not match the reviewed value"
    }
}

function Invoke-BoundedProcess {
    param(
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][int]$TimeoutSeconds,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $FileName
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in $Arguments) {
        $start.ArgumentList.Add($argument)
    }

    $process = [Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) {
            throw "$Label did not start"
        }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try {
                $process.Kill($true)
            }
            catch {
                # Preserve the timeout as the only public failure reason.
            }
            throw "$Label exceeded its bounded timeout"
        }
        [void]$stdout.GetAwaiter().GetResult()
        [void]$stderr.GetAwaiter().GetResult()
        if ($process.ExitCode -ne 0) {
            throw "$Label returned a nonzero status"
        }
    }
    finally {
        $process.Dispose()
    }
}

function Join-Bytes {
    param([Parameter(Mandatory = $true)][object[]]$Chunks)

    $stream = [IO.MemoryStream]::new()
    try {
        foreach ($chunk in $Chunks) {
            $bytes = [byte[]]$chunk
            $stream.Write($bytes, 0, $bytes.Length)
        }
        return $stream.ToArray()
    }
    finally {
        $stream.Dispose()
    }
}

function Get-DerLength {
    param([Parameter(Mandatory = $true)][int]$Length)

    if ($Length -lt 0) {
        throw "negative DER length"
    }
    if ($Length -lt 128) {
        return [byte[]]@([byte]$Length)
    }
    $parts = [Collections.Generic.List[byte]]::new()
    $remaining = $Length
    while ($remaining -ne 0) {
        $parts.Add([byte]($remaining -band 0xff))
        $remaining = $remaining -shr 8
    }
    $parts.Reverse()
    $result = [Collections.Generic.List[byte]]::new()
    $result.Add([byte](0x80 -bor $parts.Count))
    $result.AddRange($parts)
    return $result.ToArray()
}

function New-DerValue {
    param(
        [Parameter(Mandatory = $true)][byte]$Tag,
        [Parameter(Mandatory = $true)][byte[]]$Content
    )

    return Join-Bytes -Chunks @(
        [byte[]]@($Tag),
        (Get-DerLength -Length $Content.Length),
        $Content
    )
}

function Get-ReconstructedSpki {
    param([Parameter(Mandatory = $true)]$Certificate)

    if ($Certificate.PublicKey.Oid.Value -ne $rsaEncryptionOid) {
        throw "target public-key algorithm was not reviewed RSA"
    }
    $rsaOidDer = [byte[]]@(0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01)
    $parameters = [byte[]]$Certificate.PublicKey.EncodedParameters.RawData
    if ((Get-LowerHex -Bytes $parameters) -ne "0500") {
        throw "target RSA parameters were not canonical DER NULL"
    }
    $algorithm = New-DerValue -Tag 0x30 -Content (
        Join-Bytes -Chunks @($rsaOidDer, $parameters))
    $keyValue = [byte[]]$Certificate.PublicKey.EncodedKeyValue.RawData
    $bitString = New-DerValue -Tag 0x03 -Content (
        Join-Bytes -Chunks @([byte[]]@(0), $keyValue))
    return New-DerValue -Tag 0x30 -Content (
        Join-Bytes -Chunks @($algorithm, $bitString))
}

function Get-AuthenticodeHash {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Image,
        [Parameter(Mandatory = $true)][int]$ChecksumOffset,
        [Parameter(Mandatory = $true)][int]$SecurityDirectoryOffset,
        [Parameter(Mandatory = $true)][int]$CertificateOffset,
        [Parameter(Mandatory = $true)][int]$CertificateSize
    )

    $certificateEnd = $CertificateOffset + $CertificateSize
    if ($ChecksumOffset -le 0 -or
        $SecurityDirectoryOffset -le ($ChecksumOffset + 4) -or
        $CertificateOffset -le ($SecurityDirectoryOffset + 8) -or
        $certificateEnd -gt $Image.Length) {
        throw "target PE Authenticode ranges were invalid"
    }
    $hash = [Security.Cryptography.IncrementalHash]::CreateHash(
        [Security.Cryptography.HashAlgorithmName]::SHA384)
    try {
        $hash.AppendData($Image, 0, $ChecksumOffset)
        $hash.AppendData(
            $Image,
            $ChecksumOffset + 4,
            $SecurityDirectoryOffset - ($ChecksumOffset + 4))
        $hash.AppendData(
            $Image,
            $SecurityDirectoryOffset + 8,
            $CertificateOffset - ($SecurityDirectoryOffset + 8))
        if ($certificateEnd -lt $Image.Length) {
            $hash.AppendData($Image, $certificateEnd, $Image.Length - $certificateEnd)
        }
        return $hash.GetHashAndReset()
    }
    finally {
        $hash.Dispose()
    }
}

function Get-StaticTargetEvidence {
    param([Parameter(Mandatory = $true)][string]$Path)

    Assert-PinnedFile -Path $Path -Length $targetLength -Sha256 $targetSha256 -Label "target"
    Add-Type -AssemblyName System.Security.Cryptography.Pkcs
    Add-Type -AssemblyName System.Formats.Asn1

    $image = [IO.File]::ReadAllBytes($Path)
    try {
        if ([BitConverter]::ToUInt16($image, 0) -ne 0x5a4d) {
            throw "target DOS header was invalid"
        }
        $peOffset = [BitConverter]::ToInt32($image, 0x3c)
        if ($peOffset -lt 0x40 -or $peOffset -gt ($image.Length - 256) -or
            [BitConverter]::ToUInt32($image, $peOffset) -ne 0x00004550) {
            throw "target PE header was invalid"
        }
        $machine = [BitConverter]::ToUInt16($image, $peOffset + 4)
        $optionalOffset = $peOffset + 24
        if ($machine -ne $targetMachine -or
            [BitConverter]::ToUInt16($image, $optionalOffset) -ne 0x020b) {
            throw "target was not the reviewed AMD64 PE32+ image"
        }
        $checksumOffset = $optionalOffset + 64
        $securityDirectoryOffset = $optionalOffset + 112 + (4 * 8)
        $certificateOffset = [int][BitConverter]::ToUInt32($image, $securityDirectoryOffset)
        $certificateSize = [int][BitConverter]::ToUInt32($image, $securityDirectoryOffset + 4)
        if ($certificateOffset -le 0 -or $certificateSize -le 8 -or
            ($certificateOffset + $certificateSize) -ne $image.Length) {
            throw "target certificate table was not one reviewed terminal table"
        }
        $winCertificateLength = [int][BitConverter]::ToUInt32($image, $certificateOffset)
        $winCertificateRevision = [BitConverter]::ToUInt16($image, $certificateOffset + 4)
        $winCertificateType = [BitConverter]::ToUInt16($image, $certificateOffset + 6)
        if ($winCertificateLength -ne $certificateSize -or
            $winCertificateRevision -ne 0x0200 -or
            $winCertificateType -ne 0x0002) {
            throw "target WIN_CERTIFICATE shape changed"
        }

        $encodedCms = [byte[]]::new($winCertificateLength - 8)
        [Array]::Copy($image, $certificateOffset + 8, $encodedCms, 0, $encodedCms.Length)
        $cms = [Security.Cryptography.Pkcs.SignedCms]::new()
        $cms.Decode($encodedCms)
        $cms.CheckSignature($true)
        if ($cms.SignerInfos.Count -ne 1) {
            throw "target primary signature cardinality changed"
        }
        $signer = $cms.SignerInfos[0]
        if ($signer.DigestAlgorithm.Value -ne $targetDigestOid -or
            $signer.CounterSignerInfos.Count -ne 1) {
            throw "target digest or timestamp cardinality changed"
        }
        $nestedCount = 0
        foreach ($attribute in $signer.UnsignedAttributes) {
            if ($attribute.Oid.Value -eq $nestedSignatureOid) {
                $nestedCount += $attribute.Values.Count
            }
        }
        if ($nestedCount -ne 0) {
            throw "target gained an unreviewed nested signature"
        }

        $contentReader = [System.Formats.Asn1.AsnReader]::new(
            $cms.ContentInfo.Content,
            [System.Formats.Asn1.AsnEncodingRules]::DER)
        $indirectData = $contentReader.ReadSequence()
        [void]$indirectData.ReadEncodedValue()
        $digestInfo = $indirectData.ReadSequence()
        $digestAlgorithm = $digestInfo.ReadSequence()
        $contentDigestOid = $digestAlgorithm.ReadObjectIdentifier()
        if ($digestAlgorithm.HasData) {
            [void]$digestAlgorithm.ReadEncodedValue()
        }
        $signedContentDigest = $digestInfo.ReadOctetString()
        if ($contentReader.HasData -or $indirectData.HasData -or $digestInfo.HasData -or
            $contentDigestOid -ne $targetDigestOid) {
            throw "target Authenticode indirect-data shape changed"
        }
        $signedContentDigestHex = Get-LowerHex -Bytes $signedContentDigest
        if ($signedContentDigestHex -ne $targetAuthenticodeSha384) {
            throw "target signed Authenticode digest changed"
        }
        $calculatedAuthenticode = Get-AuthenticodeHash `
            -Image $image `
            -ChecksumOffset $checksumOffset `
            -SecurityDirectoryOffset $securityDirectoryOffset `
            -CertificateOffset $certificateOffset `
            -CertificateSize $certificateSize
        if ((Get-LowerHex -Bytes $calculatedAuthenticode) -ne $targetAuthenticodeSha384) {
            throw "target PE bytes did not match the signed Authenticode digest"
        }

        $certificate = $signer.Certificate
        if ($null -eq $certificate) {
            throw "target signer certificate was absent"
        }
        $rsa = [Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey(
            $certificate)
        if ($null -eq $rsa) {
            throw "target signer key was not RSA"
        }
        try {
            $exportedSpki = $rsa.ExportSubjectPublicKeyInfo()
        }
        finally {
            $rsa.Dispose()
        }
        $reconstructedSpki = Get-ReconstructedSpki -Certificate $certificate
        $exportedDigest = Get-LowerHex -Bytes (
            [Security.Cryptography.SHA256]::HashData($exportedSpki))
        $reconstructedDigest = Get-LowerHex -Bytes (
            [Security.Cryptography.SHA256]::HashData($reconstructedSpki))
        if ($exportedDigest -ne $targetSpkiSha256 -or
            $reconstructedDigest -ne $targetSpkiSha256) {
            throw "target signer SPKI did not match both reviewed derivations"
        }

        $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
        if ($version.FileVersion -ne $targetVersion -or $version.ProductVersion -ne $targetVersion) {
            throw "target version resource changed"
        }

        return [pscustomobject]@{
            Machine = $machine
            CertificateTableSize = $certificateSize
            PrimarySigners = $cms.SignerInfos.Count
            ClassicCountersigners = $signer.CounterSignerInfos.Count
            NestedSignatures = $nestedCount
            DigestOid = $contentDigestOid
            Version = $version.FileVersion
        }
    }
    finally {
        [Array]::Clear($image, 0, $image.Length)
    }
}

if (-not ("OpenKakao.ArtifactQualification.NativeMethods" -as [type])) {
    $nativeSource = @'
using System;
using System.Runtime.InteropServices;

namespace OpenKakao.ArtifactQualification
{
    [StructLayout(LayoutKind.Sequential)]
    public struct WinTrustFileInfo
    {
        public UInt32 cbStruct;
        public IntPtr pcwszFilePath;
        public IntPtr hFile;
        public IntPtr pgKnownSubject;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct StrongSignPara
    {
        public UInt32 cbSize;
        public UInt32 dwInfoChoice;
        public IntPtr pszOID;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WinTrustSignatureSettings
    {
        public UInt32 cbStruct;
        public UInt32 dwIndex;
        public UInt32 dwFlags;
        public UInt32 cSecondarySigs;
        public UInt32 dwVerifiedSigIndex;
        public IntPtr pCryptoPolicy;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct WinTrustData
    {
        public UInt32 cbStruct;
        public IntPtr pPolicyCallbackData;
        public IntPtr pSIPClientData;
        public UInt32 dwUIChoice;
        public UInt32 fdwRevocationChecks;
        public UInt32 dwUnionChoice;
        public IntPtr pFile;
        public UInt32 dwStateAction;
        public IntPtr hWVTStateData;
        public IntPtr pwszURLReference;
        public UInt32 dwProvFlags;
        public UInt32 dwUIContext;
        public IntPtr pSignatureSettings;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct FileTime
    {
        public UInt32 dwLowDateTime;
        public UInt32 dwHighDateTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct CryptProviderData
    {
        public UInt32 cbStruct;
        public IntPtr pWintrustData;
        public Int32 fOpenedFile;
        public IntPtr hWndParent;
        public IntPtr pgActionID;
        public IntPtr hProv;
        public UInt32 dwError;
        public UInt32 dwRegSecuritySettings;
        public UInt32 dwRegPolicySettings;
        public IntPtr psPfns;
        public UInt32 cdwTrustStepErrors;
        public IntPtr padwTrustStepErrors;
        public UInt32 chStores;
        public IntPtr pahStores;
        public UInt32 dwEncoding;
        public IntPtr hMsg;
        public UInt32 csSigners;
        public IntPtr pasSigners;
        public UInt32 csProvPrivData;
        public IntPtr pasProvPrivData;
        public UInt32 dwSubjectChoice;
        public IntPtr pPDSip;
        public IntPtr pszUsageOID;
        public Int32 fRecallWithState;
        public FileTime sftSystemTime;
        public IntPtr pszCTLSignerUsageOID;
        public UInt32 dwProvFlags;
        public UInt32 dwFinalError;
        public IntPtr pRequestUsage;
        public UInt32 dwTrustPubSettings;
        public UInt32 dwUIStateFlags;
        public IntPtr pSigState;
        public IntPtr pSigSettings;
    }

    public static class NativeMethods
    {
        [DllImport("wintrust.dll", ExactSpelling = true, PreserveSig = true)]
        public static extern Int32 WinVerifyTrust(
            IntPtr hwnd,
            IntPtr actionId,
            IntPtr trustData);

        [DllImport("wintrust.dll", ExactSpelling = true)]
        public static extern IntPtr WTHelperProvDataFromStateData(IntPtr stateData);

        [DllImport("shell32.dll", ExactSpelling = true)]
        public static extern Int32 SHGetKnownFolderPath(
            ref Guid folderId,
            UInt32 flags,
            IntPtr token,
            out IntPtr path);

        [DllImport("ole32.dll", ExactSpelling = true)]
        public static extern void CoTaskMemFree(IntPtr memory);
    }
}
'@
    Add-Type -TypeDefinition $nativeSource -Language CSharp
}

function Get-KnownFolderPath {
    param([Parameter(Mandatory = $true)][Guid]$FolderId)

    $pointer = [IntPtr]::Zero
    $id = $FolderId
    $status = [OpenKakao.ArtifactQualification.NativeMethods]::SHGetKnownFolderPath(
        [ref]$id,
        0,
        [IntPtr]::Zero,
        [ref]$pointer)
    try {
        if ($status -ne 0 -or $pointer -eq [IntPtr]::Zero) {
            throw "known-folder resolution failed"
        }
        return [IO.Path]::GetFullPath([Runtime.InteropServices.Marshal]::PtrToStringUni($pointer))
    }
    finally {
        if ($pointer -ne [IntPtr]::Zero) {
            [OpenKakao.ArtifactQualification.NativeMethods]::CoTaskMemFree($pointer)
        }
    }
}

function Invoke-ExactWinTrust {
    param([Parameter(Mandatory = $true)][string]$Path)

    $marshal = [Runtime.InteropServices.Marshal]
    $file = $null
    $pathPointer = [IntPtr]::Zero
    $oidPointer = [IntPtr]::Zero
    $actionPointer = [IntPtr]::Zero
    $fileInfoPointer = [IntPtr]::Zero
    $policyPointer = [IntPtr]::Zero
    $settingsPointer = [IntPtr]::Zero
    $dataPointer = [IntPtr]::Zero
    $verifyAttempted = $false
    $closeAttempted = $false
    $verifyStatus = [int]::MinValue
    $closeStatus = [int]::MinValue
    try {
        $file = [IO.File]::Open(
            $Path,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::Read)
        $pathPointer = $marshal::StringToHGlobalUni([IO.Path]::GetFullPath($Path))
        $oidPointer = $marshal::StringToHGlobalAnsi("1.3.6.1.4.1.311.72.1.1")

        $fileInfo = [OpenKakao.ArtifactQualification.WinTrustFileInfo]::new()
        $fileInfo.cbStruct = [uint32]$marshal::SizeOf($fileInfo)
        $fileInfo.pcwszFilePath = $pathPointer
        $fileInfo.hFile = $file.SafeFileHandle.DangerousGetHandle()
        $fileInfo.pgKnownSubject = [IntPtr]::Zero
        $fileInfoPointer = $marshal::AllocHGlobal($marshal::SizeOf($fileInfo))
        $marshal::StructureToPtr($fileInfo, $fileInfoPointer, $false)

        $strongPolicy = [OpenKakao.ArtifactQualification.StrongSignPara]::new()
        $strongPolicy.cbSize = [uint32]$marshal::SizeOf($strongPolicy)
        $strongPolicy.dwInfoChoice = 2
        $strongPolicy.pszOID = $oidPointer
        $policyPointer = $marshal::AllocHGlobal($marshal::SizeOf($strongPolicy))
        $marshal::StructureToPtr($strongPolicy, $policyPointer, $false)

        $settings = [OpenKakao.ArtifactQualification.WinTrustSignatureSettings]::new()
        $settings.cbStruct = [uint32]$marshal::SizeOf($settings)
        $settings.dwIndex = 0
        $settings.dwFlags = 0x00000002
        $settings.cSecondarySigs = 0
        $settings.dwVerifiedSigIndex = 0
        $settings.pCryptoPolicy = $policyPointer
        $settingsPointer = $marshal::AllocHGlobal($marshal::SizeOf($settings))
        $marshal::StructureToPtr($settings, $settingsPointer, $false)

        $data = [OpenKakao.ArtifactQualification.WinTrustData]::new()
        $data.cbStruct = [uint32]$marshal::SizeOf($data)
        $data.pPolicyCallbackData = [IntPtr]::Zero
        $data.pSIPClientData = [IntPtr]::Zero
        $data.dwUIChoice = 2
        $data.fdwRevocationChecks = 1
        $data.dwUnionChoice = 1
        $data.pFile = $fileInfoPointer
        $data.dwStateAction = 1
        $data.hWVTStateData = [IntPtr]::Zero
        $data.pwszURLReference = [IntPtr]::Zero
        $data.dwProvFlags = 0x00003080
        $data.dwUIContext = 0
        $data.pSignatureSettings = $settingsPointer
        $dataPointer = $marshal::AllocHGlobal($marshal::SizeOf($data))
        $marshal::StructureToPtr($data, $dataPointer, $false)

        $action = [Guid]"00aac56b-cd44-11d0-8cc2-00c04fc295ee"
        $actionPointer = $marshal::AllocHGlobal($marshal::SizeOf($action))
        $marshal::StructureToPtr($action, $actionPointer, $false)

        $verifyAttempted = $true
        $verifyStatus = [OpenKakao.ArtifactQualification.NativeMethods]::WinVerifyTrust(
            [IntPtr](-1),
            $actionPointer,
            $dataPointer)
        $data = $marshal::PtrToStructure(
            $dataPointer,
            [type][OpenKakao.ArtifactQualification.WinTrustData])
        $settings = $marshal::PtrToStructure(
            $settingsPointer,
            [type][OpenKakao.ArtifactQualification.WinTrustSignatureSettings])

        $providerPresent = $false
        $providerFlags = [uint32]0
        $providerError = [uint32]0
        $providerFinalError = [uint32]0
        $providerSigners = [uint32]0
        $providerSubjectChoice = [uint32]0
        $providerRecall = $false
        $providerPointerMatch = $false
        $providerSize = 0
        if ($data.hWVTStateData -ne [IntPtr]::Zero) {
            $providerPointer = [OpenKakao.ArtifactQualification.NativeMethods]::WTHelperProvDataFromStateData(
                $data.hWVTStateData)
            if ($providerPointer -ne [IntPtr]::Zero) {
                $providerPresent = $true
                $provider = $marshal::PtrToStructure(
                    $providerPointer,
                    [type][OpenKakao.ArtifactQualification.CryptProviderData])
                $providerSize = $marshal::SizeOf($provider)
                if ($provider.cbStruct -ne $providerSize) {
                    throw "WinTrust provider structure size changed"
                }
                $providerFlags = $provider.dwProvFlags
                $providerError = $provider.dwError
                $providerFinalError = $provider.dwFinalError
                $providerSigners = $provider.csSigners
                $providerSubjectChoice = $provider.dwSubjectChoice
                $providerRecall = $provider.fRecallWithState -ne 0
                $providerPointerMatch = (
                    $provider.pWintrustData -eq $dataPointer -and
                    $provider.pgActionID -eq $actionPointer -and
                    $provider.pSigSettings -eq $settingsPointer)
            }
        }

        if ($verifyStatus -ne 0 -or -not $providerPresent -or
            $providerError -ne 0 -or $providerFinalError -ne 0 -or
            $providerSigners -ne 1 -or $providerSubjectChoice -ne 1 -or
            $providerRecall -or -not $providerPointerMatch -or
            $settings.cSecondarySigs -ne 0 -or $settings.dwVerifiedSigIndex -ne 0 -or
            ($settings.dwFlags -band 0x0000ffff) -ne 0x00000002) {
            throw "target did not satisfy the exact positive WinTrust provider path"
        }

        $data.dwStateAction = 2
        $marshal::StructureToPtr($data, $dataPointer, $false)
        $closeAttempted = $true
        $closeStatus = [OpenKakao.ArtifactQualification.NativeMethods]::WinVerifyTrust(
            [IntPtr](-1),
            $actionPointer,
            $dataPointer)
        if ($closeStatus -ne 0) {
            throw "WinTrust state close failed"
        }

        return [pscustomobject]@{
            VerifyStatus = $verifyStatus
            CloseStatus = $closeStatus
            SecondarySignatures = $settings.cSecondarySigs
            VerifiedSignatureIndex = $settings.dwVerifiedSigIndex
            SignatureFlags = $settings.dwFlags
            ProviderSize = $providerSize
            ProviderFlags = $providerFlags
            ProviderSigners = $providerSigners
            ProviderSubjectChoice = $providerSubjectChoice
            ProviderPointerMatch = $providerPointerMatch
        }
    }
    finally {
        if ($verifyAttempted -and -not $closeAttempted -and
            $dataPointer -ne [IntPtr]::Zero -and $actionPointer -ne [IntPtr]::Zero) {
            try {
                $data = $marshal::PtrToStructure(
                    $dataPointer,
                    [type][OpenKakao.ArtifactQualification.WinTrustData])
                $data.dwStateAction = 2
                $marshal::StructureToPtr($data, $dataPointer, $false)
                [void][OpenKakao.ArtifactQualification.NativeMethods]::WinVerifyTrust(
                    [IntPtr](-1),
                    $actionPointer,
                    $dataPointer)
            }
            catch {
                # The original qualification failure remains authoritative.
            }
        }
        foreach ($pointer in @(
            $dataPointer,
            $settingsPointer,
            $policyPointer,
            $fileInfoPointer,
            $actionPointer,
            $oidPointer,
            $pathPointer)) {
            if ($pointer -ne [IntPtr]::Zero) {
                $marshal::FreeHGlobal($pointer)
            }
        }
        if ($null -ne $file) {
            $file.Dispose()
        }
    }
}

function Find-KakaoTargets {
    param([Parameter(Mandatory = $true)][string[]]$Roots)

    $results = [Collections.Generic.List[IO.FileInfo]]::new()
    foreach ($root in $Roots) {
        if ([IO.Directory]::Exists($root)) {
            foreach ($item in Get-ChildItem -LiteralPath $root -Recurse -File -Filter "KakaoTalk.exe") {
                $results.Add($item)
            }
        }
    }
    return @($results)
}

$runnerTemp = [IO.Path]::GetFullPath($env:RUNNER_TEMP)
$runnerPrefix = $runnerTemp.TrimEnd(
    [IO.Path]::DirectorySeparatorChar,
    [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
$qualificationRoot = [IO.Path]::GetFullPath((Join-Path $runnerTemp (
    "openkakao-kakao-x64-" + [Guid]::NewGuid().ToString("N"))))
if (-not $qualificationRoot.StartsWith($runnerPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "qualification root escaped RUNNER_TEMP"
}

$installerPath = Join-Path $qualificationRoot "KakaoTalk_Setup_x64.exe"
$sevenZipMsi = Join-Path $qualificationRoot "7z-x64.msi"
$sevenZipImage = Join-Path $qualificationRoot "7z-image"
$staticRoot = Join-Path $qualificationRoot "static-target"
$overrideRoot = Join-Path $qualificationRoot "override-install"
$firewallRule = "OpenKakaoArtifactQualification" + [Guid]::NewGuid().ToString("N")
$ifeoKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\KakaoTalk.exe"

[IO.Directory]::CreateDirectory($qualificationRoot) | Out-Null
$retrievedAt = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
$installerResponse = Invoke-WebRequest -Uri $installerUri -OutFile $installerPath -PassThru
Invoke-WebRequest -Uri $sevenZipUri -OutFile $sevenZipMsi | Out-Null
Assert-PinnedFile -Path $installerPath -Length $installerLength -Sha256 $installerSha256 -Label "installer"
Assert-PinnedFile -Path $sevenZipMsi -Length $sevenZipLength -Sha256 $sevenZipSha256 -Label "7-Zip MSI"

[IO.Directory]::CreateDirectory($sevenZipImage) | Out-Null
Invoke-BoundedProcess `
    -FileName "$env:SystemRoot\System32\msiexec.exe" `
    -Arguments @("/a", $sevenZipMsi, "/qn", "TARGETDIR=$sevenZipImage") `
    -TimeoutSeconds 120 `
    -Label "7-Zip administrative extraction"
$sevenZipCandidates = @(Get-ChildItem -LiteralPath $sevenZipImage -Recurse -File -Filter "7z.exe")
if ($sevenZipCandidates.Count -ne 1) {
    throw "7-Zip administrative image did not contain exactly one executable"
}
$sevenZip = $sevenZipCandidates[0].FullName
[IO.Directory]::CreateDirectory($staticRoot) | Out-Null
Invoke-BoundedProcess `
    -FileName $sevenZip `
    -Arguments @("x", "-tNsis", "-y", "-bd", "-bb0", "-o$staticRoot", $installerPath, "KakaoTalk.exe") `
    -TimeoutSeconds 120 `
    -Label "static NSIS extraction"
$staticCandidates = @(Get-ChildItem -LiteralPath $staticRoot -Recurse -File -Filter "KakaoTalk.exe")
if ($staticCandidates.Count -ne 1) {
    throw "static extraction did not produce exactly one target"
}
$staticTarget = $staticCandidates[0].FullName
$staticEvidence = Get-StaticTargetEvidence -Path $staticTarget
$winTrustEvidence = Invoke-ExactWinTrust -Path $staticTarget

$programFiles64 = Get-KnownFolderPath -FolderId ([Guid]"6d809377-6af0-444b-8957-a3773f02200e")
$programFilesX86 = Get-KnownFolderPath -FolderId ([Guid]"7c5a40ef-a0fb-4bfc-874a-c0f2e0b9fa8e")
$defaultSearchRoots = @(
    (Join-Path $programFiles64 "Kakao"),
    (Join-Path $programFilesX86 "Kakao"))
if (@(Find-KakaoTargets -Roots $defaultSearchRoots).Count -ne 0 -or
    @(Get-Process -Name "KakaoTalk" -ErrorAction SilentlyContinue).Count -ne 0 -or
    (Test-Path -LiteralPath $ifeoKey)) {
    throw "hosted runner was not clean before installer qualification"
}

$firewallInstalled = $false
$ifeoInstalled = $false
try {
    New-Item -Path $ifeoKey -Force | Out-Null
    New-ItemProperty `
        -LiteralPath $ifeoKey `
        -Name "Debugger" `
        -PropertyType String `
        -Value "$env:SystemRoot\System32\cmd.exe /d /c exit 225" `
        -Force | Out-Null
    $ifeoInstalled = $true

    New-NetFirewallRule `
        -Name $firewallRule `
        -DisplayName $firewallRule `
        -Direction Outbound `
        -Action Block `
        -Profile Any `
        -Enabled True | Out-Null
    $firewallInstalled = $true

    $installerArguments = @("/S")
    if ($InstallMode -eq "Override") {
        [IO.Directory]::CreateDirectory($overrideRoot) | Out-Null
        $installerArguments += "/D=$overrideRoot"
    }
    Invoke-BoundedProcess `
        -FileName $installerPath `
        -Arguments $installerArguments `
        -TimeoutSeconds 240 `
        -Label "network-isolated installer"
}
finally {
    if ($firewallInstalled) {
        Remove-NetFirewallRule -Name $firewallRule -ErrorAction SilentlyContinue
    }
    if ($ifeoInstalled -and (Test-Path -LiteralPath $ifeoKey)) {
        Remove-Item -LiteralPath $ifeoKey -Recurse -Force
    }
}

if (@(Get-Process -Name "KakaoTalk" -ErrorAction SilentlyContinue).Count -ne 0) {
    throw "KakaoTalk unexpectedly executed during artifact qualification"
}

$defaultTargets = @(Find-KakaoTargets -Roots $defaultSearchRoots)
$overrideTargets = @(Find-KakaoTargets -Roots @($overrideRoot))
$overrideAccepted = $overrideTargets.Count -eq 1
if ($InstallMode -eq "Default") {
    if ($defaultTargets.Count -ne 1 -or $overrideTargets.Count -ne 0) {
        throw "default installer behavior did not produce one known-folder target"
    }
    $installedTarget = $defaultTargets[0]
}
else {
    if ($overrideAccepted) {
        if ($defaultTargets.Count -ne 0) {
            throw "override installer behavior produced targets in multiple roots"
        }
        $installedTarget = $overrideTargets[0]
    }
    else {
        if ($defaultTargets.Count -ne 1 -or $overrideTargets.Count -ne 0) {
            throw "override installer behavior was ambiguous"
        }
        $installedTarget = $defaultTargets[0]
    }
}
Assert-PinnedFile `
    -Path $installedTarget.FullName `
    -Length $targetLength `
    -Sha256 $targetSha256 `
    -Label "installed target"

$rootKind = "temporary-override"
$relativeComponents = @()
if ($installedTarget.FullName.StartsWith(
    $programFiles64.TrimEnd('\') + '\',
    [StringComparison]::OrdinalIgnoreCase)) {
    $rootKind = "ProgramFiles64"
    $relative = [IO.Path]::GetRelativePath($programFiles64, $installedTarget.FullName)
    $relativeComponents = @($relative -split '[\\/]')
}
elseif ($installedTarget.FullName.StartsWith(
    $programFilesX86.TrimEnd('\') + '\',
    [StringComparison]::OrdinalIgnoreCase)) {
    $rootKind = "ProgramFilesX86"
    $relative = [IO.Path]::GetRelativePath($programFilesX86, $installedTarget.FullName)
    $relativeComponents = @($relative -split '[\\/]')
}
elseif ($overrideAccepted -and $installedTarget.FullName.StartsWith(
    $overrideRoot.TrimEnd('\') + '\',
    [StringComparison]::OrdinalIgnoreCase)) {
    $relative = [IO.Path]::GetRelativePath($overrideRoot, $installedTarget.FullName)
    $relativeComponents = @($relative -split '[\\/]')
}
else {
    throw "installed target escaped every qualified root"
}
if ($relativeComponents.Count -lt 1 -or $relativeComponents.Count -gt 8 -or
    @($relativeComponents | Where-Object { $_ -notmatch '^[\x20-\x7e]{1,64}$' }).Count -ne 0) {
    throw "installed target relation was not portable ASCII"
}

$lastModified = "absent"
$headerText = $installerResponse.Headers.ToString()
if ($headerText -match '(?im)^Last-Modified:\s*(?<value>[^\r\n]+)') {
    $lastModified = $Matches["value"].Trim()
}
$expectedProviderFlags = [Convert]::ToUInt32('80003080', 16)
$providerCompatibility = $winTrustEvidence.ProviderFlags -eq $expectedProviderFlags

Write-Output "qualification_schema=openkakao-windows-kakao-x64-observation-v1"
Write-Output "install_mode=$InstallMode"
Write-Output "retrieved_utc=$retrievedAt"
Write-Output "installer_last_modified=$lastModified"
Write-Output "installer_bytes=$installerLength"
Write-Output "installer_sha256=$installerSha256"
Write-Output "target_version=$($staticEvidence.Version)"
Write-Output ("target_machine=0x{0:x4}" -f $staticEvidence.Machine)
Write-Output "target_bytes=$targetLength"
Write-Output "target_whole_file_sha256=$targetSha256"
Write-Output "target_leaf_spki_sha256=$targetSpkiSha256"
Write-Output "target_signature_primary=$($staticEvidence.PrimarySigners)"
Write-Output "target_signature_secondary=$($winTrustEvidence.SecondarySignatures)"
Write-Output "target_classic_countersigners=$($staticEvidence.ClassicCountersigners)"
Write-Output "target_nested_signatures=$($staticEvidence.NestedSignatures)"
Write-Output "target_authenticode_digest_oid=$($staticEvidence.DigestOid)"
Write-Output "target_authenticode_sha384=$targetAuthenticodeSha384"
Write-Output ("wintrust_provider_flags=0x{0:x8}" -f $winTrustEvidence.ProviderFlags)
Write-Output "wintrust_provider_policy_source_compatible=$($providerCompatibility.ToString().ToLowerInvariant())"
Write-Output "wintrust_provider_size=$($winTrustEvidence.ProviderSize)"
Write-Output "wintrust_provider_pointer_match=$($winTrustEvidence.ProviderPointerMatch.ToString().ToLowerInvariant())"
Write-Output "install_root_kind=$rootKind"
Write-Output "install_relative_components=$($relativeComponents -join '/')"
Write-Output "override_accepted=$($overrideAccepted.ToString().ToLowerInvariant())"
Write-Output "product_binary_executed=false"
Write-Output "network_isolated_during_installer=true"
