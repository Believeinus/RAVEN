using System.Security.Cryptography.X509Certificates;
using Windows.Win32;
using Windows.Win32.Foundation;
using Windows.Win32.Security.Cryptography.Catalog;
using Windows.Win32.Security.WinTrust;

namespace RatScan.Native.Signing;

public enum SignatureStatus
{
    /// <summary>Verification could not be performed (file missing, locked, error).</summary>
    Unknown = 0,

    /// <summary>No signature at all — neither embedded nor in any catalog.</summary>
    Unsigned,

    /// <summary>Signed, chain valid, root trusted.</summary>
    Valid,

    /// <summary>Signed, but the file has been modified since signing.</summary>
    TamperedDigest,

    /// <summary>Signed by a certificate that has expired.</summary>
    Expired,

    /// <summary>Signed by a revoked certificate.</summary>
    Revoked,

    /// <summary>Chain terminates in a root this machine does not trust.</summary>
    UntrustedRoot,

    /// <summary>Explicitly distrusted by policy.</summary>
    Distrusted,

    /// <summary>Signed but rejected for some other policy reason.</summary>
    Invalid,
}

public sealed record SignatureInfo
{
    public required string FilePath { get; init; }
    public required SignatureStatus Status { get; init; }

    /// <summary>Subject common name of the signing certificate, when obtainable.</summary>
    public string? SignerName { get; init; }

    /// <summary>
    /// True when the signature came from a security catalog rather than being embedded
    /// in the file. Most Windows binaries are catalog-signed.
    /// </summary>
    public bool IsCatalogSigned { get; init; }

    public int StatusCode { get; init; }
    public string? Error { get; init; }

    public bool IsTrusted => Status == SignatureStatus.Valid;
}

/// <summary>
/// Authenticode verification, embedded signatures <em>and</em> security catalogs.
/// <para>
/// INVARIANT: the catalog path is not optional. The large majority of Windows' own
/// binaries carry no embedded signature — they are vouched for by catalogs in
/// <c>%SystemRoot%\System32\CatRoot</c>. A verifier that only checks embedded
/// signatures reports most of the operating system as unsigned, which floods the
/// findings list with noise and buries the handful of genuinely unsigned binaries
/// that matter. Getting this wrong does not fail loudly; it fails by making the tool
/// useless.
/// </para>
/// </summary>
public static unsafe class AuthenticodeVerifier
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const int TrustENoSignature = unchecked((int)0x800B0100);
    private const int TrustEBadDigest = unchecked((int)0x80096010);
    private const int CertEExpired = unchecked((int)0x800B0101);
    private const int CertERevoked = unchecked((int)0x800B010C);
    private const int CertEUntrustedRoot = unchecked((int)0x800B0109);
    private const int TrustEExplicitDistrust = unchecked((int)0x800B0111);
    private const int TrustESubjectNotTrusted = unchecked((int)0x800B0004);
    private const int CryptENoMatch = unchecked((int)0x80092009);

    /// <summary>CERT_NAME_SIMPLE_DISPLAY_TYPE.</summary>
    private const uint CertNameSimpleDisplay = 4;

    public static SignatureInfo Verify(string filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath) || !File.Exists(filePath))
        {
            return new SignatureInfo
            {
                FilePath = filePath,
                Status = SignatureStatus.Unknown,
                Error = "file not found or path unreadable",
            };
        }

        var embedded = VerifyEmbedded(filePath);

        // Only fall through to catalogs when there is genuinely no embedded signature.
        // A present-but-invalid embedded signature is a real finding and must not be
        // masked by a catalog that happens to also vouch for the file.
        if (embedded.Status != SignatureStatus.Unsigned)
        {
            return embedded;
        }

        var catalog = VerifyViaCatalog(filePath);
        return catalog ?? embedded;
    }

    private static SignatureInfo VerifyEmbedded(string filePath)
    {
        fixed (char* path = filePath)
        {
            var fileInfo = new WINTRUST_FILE_INFO
            {
                cbStruct = (uint)sizeof(WINTRUST_FILE_INFO),
                pcwszFilePath = new PCWSTR(path),
            };

            var data = NewTrustData();
            data.dwUnionChoice = WINTRUST_DATA_UNION_CHOICE.WTD_CHOICE_FILE;
            data.Anonymous.pFile = &fileInfo;

            return RunVerify(filePath, ref data, catalogSigned: false);
        }
    }

    /// <summary>
    /// Hashes the file, looks the hash up across the installed catalogs, and verifies
    /// against the catalog that claims it.
    /// </summary>
    private static SignatureInfo? VerifyViaCatalog(string filePath)
    {
        nint catAdmin = 0;

        try
        {
            // SHA-256 explicitly: catalogs on modern Windows are SHA-256, and letting
            // this default can silently select SHA-1 and find nothing.
            if (!PInvoke.CryptCATAdminAcquireContext2(out catAdmin, null, "SHA256", null))
            {
                return null;
            }

            using var file = File.OpenHandle(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

            uint hashSize = 0;
            PInvoke.CryptCATAdminCalcHashFromFileHandle2(catAdmin, file, ref hashSize, Span<byte>.Empty);
            if (hashSize == 0)
            {
                return null;
            }

            var hash = new byte[hashSize];
            if (!PInvoke.CryptCATAdminCalcHashFromFileHandle2(catAdmin, file, ref hashSize, hash))
            {
                return null;
            }

            var catInfoHandle = PInvoke.CryptCATAdminEnumCatalogFromHash(catAdmin, hash);
            if (catInfoHandle == 0)
            {
                // Genuinely in no catalog — the caller's "unsigned" verdict stands.
                return null;
            }

            try
            {
                var catalogInfo = new CATALOG_INFO { cbStruct = (uint)sizeof(CATALOG_INFO) };
                if (!PInvoke.CryptCATCatalogInfoFromContext(catInfoHandle, ref catalogInfo, 0))
                {
                    return null;
                }

                var catalogPath = catalogInfo.wszCatalogFile.ToString();
                var memberTag = Convert.ToHexString(hash);

                fixed (char* catPath = catalogPath)
                fixed (char* tag = memberTag)
                fixed (char* member = filePath)
                fixed (byte* hashPtr = hash)
                {
                    var wtCatalog = new WINTRUST_CATALOG_INFO
                    {
                        cbStruct = (uint)sizeof(WINTRUST_CATALOG_INFO),
                        pcwszCatalogFilePath = new PCWSTR(catPath),
                        pcwszMemberTag = new PCWSTR(tag),
                        pcwszMemberFilePath = new PCWSTR(member),
                        hMemberFile = new HANDLE(file.DangerousGetHandle()),
                        pbCalculatedFileHash = hashPtr,
                        cbCalculatedFileHash = hashSize,
                        hCatAdmin = catAdmin,
                    };

                    var data = NewTrustData();
                    data.dwUnionChoice = WINTRUST_DATA_UNION_CHOICE.WTD_CHOICE_CATALOG;
                    data.Anonymous.pCatalog = &wtCatalog;

                    return RunVerify(filePath, ref data, catalogSigned: true, signatureBearingPath: catalogPath);
                }
            }
            finally
            {
                PInvoke.CryptCATAdminReleaseCatalogContext(catAdmin, catInfoHandle, 0);
            }
        }
        catch (Exception ex)
        {
            return new SignatureInfo
            {
                FilePath = filePath,
                Status = SignatureStatus.Unknown,
                Error = $"catalog verification failed: {ex.Message}",
            };
        }
        finally
        {
            if (catAdmin != 0)
            {
                PInvoke.CryptCATAdminReleaseContext(catAdmin, 0);
            }
        }
    }

    private static WINTRUST_DATA NewTrustData() => new()
    {
        cbStruct = (uint)sizeof(WINTRUST_DATA),
        dwUIChoice = WINTRUST_DATA_UICHOICE.WTD_UI_NONE,

        // Chain revocation checking only. Full online revocation would make a scan of
        // several thousand binaries take minutes and leak a request per certificate —
        // unacceptable for a tool that is offline by default.
        fdwRevocationChecks = WINTRUST_DATA_REVOCATION_CHECKS.WTD_REVOKE_NONE,
        dwStateAction = WINTRUST_DATA_STATE_ACTION.WTD_STATEACTION_VERIFY,
        dwProvFlags = WINTRUST_DATA_PROVIDER_FLAGS.WTD_SAFER_FLAG
                      | WINTRUST_DATA_PROVIDER_FLAGS.WTD_CACHE_ONLY_URL_RETRIEVAL,
    };

    private static SignatureInfo RunVerify(
        string filePath, ref WINTRUST_DATA data, bool catalogSigned, string? signatureBearingPath = null)
    {
        var action = GenericVerifyV2;

        fixed (WINTRUST_DATA* pData = &data)
        {
            var result = PInvoke.WinVerifyTrust(HWND.Null, &action, pData);

            string? signer = null;
            try
            {
                if (result == 0)
                {
                    signer = TryReadSignerName(signatureBearingPath ?? filePath);
                }
            }
            finally
            {
                // The state handle must be closed with a second call or WinTrust leaks
                // it for the lifetime of the process — over thousands of files that is
                // a real leak, not a theoretical one.
                data.dwStateAction = WINTRUST_DATA_STATE_ACTION.WTD_STATEACTION_CLOSE;

                // Return value intentionally discarded: this call only releases the
                // state handle, and its status says nothing about the file's trust.
                _ = PInvoke.WinVerifyTrust(HWND.Null, &action, pData);
            }

            return new SignatureInfo
            {
                FilePath = filePath,
                Status = Classify(result),
                SignerName = signer,
                IsCatalogSigned = catalogSigned,
                StatusCode = result,
            };
        }
    }

    /// <summary>
    /// Reads the signing certificate's subject name.
    /// <para>
    /// Deliberately the managed certificate API rather than the WinTrust provider
    /// chain: CsWin32 exposes <c>WTHelperProvDataFromStateData</c> as returning the
    /// <em>unmanaged</em> CRYPT_PROVIDER_DATA variant while
    /// <c>WTHelperGetProvSignerFromChain</c> consumes the managed one, and bridging
    /// them needs a layout-dependent cast between two generated struct shapes. That
    /// is a poor trade for a display string. The trust <em>decision</em> — the part
    /// that actually gates a finding — still comes from WinVerifyTrust above; this
    /// only supplies the name shown next to it.
    /// </para>
    /// <para>
    /// For catalog-signed files the signature lives on the .cat file, so that is what
    /// gets read.
    /// </para>
    /// </summary>
    private static string? TryReadSignerName(string signatureBearingPath)
    {
        try
        {
            // CreateFromSignedFile is the Authenticode-aware loader: it pulls the
            // signing certificate out of the PE security directory (or the .cat).
            using var cert = new X509Certificate2(X509Certificate.CreateFromSignedFile(signatureBearingPath));
            var name = cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
            return string.IsNullOrWhiteSpace(name) ? null : name;
        }
        catch
        {
            // Unsigned, or a format the loader will not touch. The status already
            // records what WinTrust concluded; the name is simply unavailable.
            return null;
        }
    }

    private static SignatureStatus Classify(int status) => status switch
    {
        0 => SignatureStatus.Valid,
        TrustENoSignature or CryptENoMatch => SignatureStatus.Unsigned,
        TrustEBadDigest => SignatureStatus.TamperedDigest,
        CertEExpired => SignatureStatus.Expired,
        CertERevoked => SignatureStatus.Revoked,
        CertEUntrustedRoot => SignatureStatus.UntrustedRoot,
        TrustEExplicitDistrust => SignatureStatus.Distrusted,
        TrustESubjectNotTrusted => SignatureStatus.Invalid,
        _ => SignatureStatus.Invalid,
    };
}
