using System.Security.Cryptography;

namespace RatScan.Engine.Allowlist;

/// <summary>
/// Hashes the file an allowlist entry is pinned to. Abstracted so allowlist logic can
/// be tested without touching the disk — the interesting cases are "the file changed"
/// and "the file cannot be read", and both are awkward to stage for real.
/// </summary>
public interface IFileHasher
{
    /// <summary>
    /// SHA-256 of the file, or null when there is no readable file at that path.
    /// <para>
    /// Null means "could not establish", never "unchanged". Callers must treat it as a
    /// failure to verify rather than as a match.
    /// </para>
    /// </summary>
    string? Sha256(string path);
}

public sealed class FileHasher : IFileHasher
{
    public string? Sha256(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return null;
            }

            using var stream = File.OpenRead(path);
            return Convert.ToHexString(SHA256.HashData(stream));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException
                                       or NotSupportedException or ArgumentException)
        {
            return null;
        }
    }
}
