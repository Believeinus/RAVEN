using RatScan.Native.Signing;
using Xunit.Abstractions;

namespace RatScan.Tests;

public sealed class AuthenticodeTests(ITestOutputHelper output)
{
    /// <summary>
    /// The catalog invariant, stated as a measurement.
    /// <para>
    /// Most binaries in System32 carry no embedded signature — they are vouched for by
    /// catalogs. If the catalog path regressed, this number collapses and the tool
    /// would start reporting most of Windows as unsigned, drowning every real finding.
    /// </para>
    /// </summary>
    [Fact]
    public void Overwhelming_majority_of_system32_verifies_as_trusted()
    {
        var system32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System));
        var sample = Directory.EnumerateFiles(system32, "*.exe").Take(60).ToList();

        Assert.NotEmpty(sample);

        var results = sample.Select(AuthenticodeVerifier.Verify).ToList();

        var valid = results.Count(r => r.Status == SignatureStatus.Valid);
        var catalog = results.Count(r => r is { Status: SignatureStatus.Valid, IsCatalogSigned: true });
        var embedded = results.Count(r => r is { Status: SignatureStatus.Valid, IsCatalogSigned: false });
        var unsigned = results.Count(r => r.Status == SignatureStatus.Unsigned);

        output.WriteLine($"sampled={results.Count} valid={valid} (catalog={catalog} embedded={embedded}) unsigned={unsigned}");

        foreach (var bad in results.Where(r => r.Status != SignatureStatus.Valid).Take(8))
        {
            output.WriteLine($"  NOT VALID: {Path.GetFileName(bad.FilePath)} -> {bad.Status} (0x{bad.StatusCode:X8}) {bad.Error}");
        }

        var ratio = (double)valid / results.Count;
        Assert.True(ratio > 0.95, $"only {ratio:P0} of System32 verified as trusted — the catalog path is broken");

        // If this ever hits zero, embedded-only verification has silently taken over.
        Assert.True(catalog > 0, "no catalog-signed binaries were recognised at all");
    }

    [Fact]
    public void Reports_signer_name_for_a_microsoft_binary()
    {
        var path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "notepad.exe");
        if (!File.Exists(path))
        {
            path = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "svchost.exe");
        }

        var result = AuthenticodeVerifier.Verify(path);
        output.WriteLine($"{Path.GetFileName(path)}: {result.Status} catalog={result.IsCatalogSigned} signer={result.SignerName}");

        Assert.Equal(SignatureStatus.Valid, result.Status);
        Assert.NotNull(result.SignerName);
        Assert.Contains("Microsoft", result.SignerName!, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Unsigned_file_reports_unsigned_not_error()
    {
        var temp = Path.Combine(Path.GetTempPath(), $"ratscan-unsigned-{Guid.NewGuid():N}.exe");
        File.WriteAllBytes(temp, "MZ\0\0not a real pe but definitely not signed"u8.ToArray());

        try
        {
            var result = AuthenticodeVerifier.Verify(temp);
            output.WriteLine($"unsigned temp file -> {result.Status} (0x{result.StatusCode:X8})");

            // The distinction matters: "unsigned" is a finding, "error" is a blind spot.
            Assert.Equal(SignatureStatus.Unsigned, result.Status);
            Assert.Null(result.SignerName);
        }
        finally
        {
            File.Delete(temp);
        }
    }

    [Fact]
    public void Missing_file_is_unknown_rather_than_unsigned()
    {
        var result = AuthenticodeVerifier.Verify(@"C:\definitely\not\here\nothing.exe");

        // Must never claim "unsigned" for a file it could not read — that would invent
        // a finding out of a failure to look.
        Assert.Equal(SignatureStatus.Unknown, result.Status);
        Assert.NotNull(result.Error);
    }
}
