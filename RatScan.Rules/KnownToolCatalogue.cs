using System.Reflection;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace RatScan.Rules;

public enum ToolCategory
{
    Unknown,
    RemoteDesktop,
    RemoteInput,
    ScreenStream,
    Rmm,
    Tunneler,
    MeshVpn,
    RatFamily,
}

/// <summary>How often a product turns up in intrusions relative to legitimate use.</summary>
public enum AbuseLevel
{
    Low,
    Medium,
    High,
}

/// <summary>
/// One catalogued product. Identification data only — presence is a fact, and whether
/// the tool is wanted is the user's call.
/// </summary>
public sealed class KnownTool
{
    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public string? Vendor { get; set; }
    public string Category { get; set; } = "unknown";
    public string Abuse { get; set; } = "low";

    /// <summary>What someone can do to the user with this, in plain terms.</summary>
    public List<string> Capabilities { get; set; } = [];

    public List<string> Processes { get; set; } = [];
    public List<string> Services { get; set; } = [];
    public List<string> Drivers { get; set; } = [];
    public List<string> Signers { get; set; } = [];
    public List<int> Ports { get; set; } = [];
    public string? Notes { get; set; }

    public ToolCategory ParsedCategory => Category switch
    {
        "remote-desktop" => ToolCategory.RemoteDesktop,
        "remote-input" => ToolCategory.RemoteInput,
        "screen-stream" => ToolCategory.ScreenStream,
        "rmm" => ToolCategory.Rmm,
        "tunneler" => ToolCategory.Tunneler,
        "mesh-vpn" => ToolCategory.MeshVpn,
        "rat-family" => ToolCategory.RatFamily,
        _ => ToolCategory.Unknown,
    };

    public AbuseLevel ParsedAbuse => Abuse switch
    {
        "high" => AbuseLevel.High,
        "medium" => AbuseLevel.Medium,
        _ => AbuseLevel.Low,
    };

    public bool CanViewScreen => Capabilities.Contains("screen-view");
    public bool CanControlInput => Capabilities.Contains("input-control");
}

public sealed class ToolCatalogue
{
    public int Version { get; set; }
    public string? Updated { get; set; }
    public List<KnownTool> Tools { get; set; } = [];
}

/// <summary>
/// Loads the embedded rule packs.
/// <para>
/// Kept as data rather than code so the catalogue can be corrected without a rebuild,
/// and so adding a product is a two-minute edit rather than a development task —
/// remote-access tooling appears faster than release cycles.
/// </para>
/// </summary>
public static class KnownToolCatalogue
{
    private static readonly Lazy<ToolCatalogue> Loaded = new(Load, LazyThreadSafetyMode.ExecutionAndPublication);

    public static ToolCatalogue Instance => Loaded.Value;

    public static IReadOnlyList<KnownTool> Tools => Instance.Tools;

    private static ToolCatalogue Load()
    {
        var assembly = Assembly.GetExecutingAssembly();
        var name = assembly.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith("known-tools.yaml", StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException(
                "known-tools.yaml is not embedded in RatScan.Rules. Without the catalogue the "
                + "scanner cannot identify any remote-access product by name.");

        using var stream = assembly.GetManifestResourceStream(name)
            ?? throw new InvalidOperationException($"Embedded resource '{name}' could not be opened.");

        using var reader = new StreamReader(stream);

        var deserializer = new DeserializerBuilder()
            .WithNamingConvention(HyphenatedNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();

        return deserializer.Deserialize<ToolCatalogue>(reader)
               ?? throw new InvalidOperationException("known-tools.yaml deserialised to nothing.");
    }
}
