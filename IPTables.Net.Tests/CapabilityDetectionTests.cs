using System;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.Adapter.Client;
using IPTables.Net.Iptables.Helpers;
namespace IPTables.Net.Tests;
public class CapabilityDetectionTests
{
    private static IPTablesBinaryAdapterClient Client(ScriptedSystem fake) => new(4, new IpTablesSystem(fake, new RecordingAdapter()), "iptables");
    [Theory]
    [InlineData("iptables v1.4.20", false)] [InlineData("iptables v1.4.21", true)] [InlineData("iptables v1.4.22", true)]
    [InlineData("iptables v1.8.11 (legacy)\n", true)] [InlineData(" \tip6tables v1.8.10 (nf_tables)\n", true)]
    public void IptablesVersionsAndSynproxyBoundary(string output, bool supported)
    {
        var fake = new ScriptedSystem { Respond = (_, _) => new(output) }; using var client = Client(fake);
        Assert.Equal(supported, SynProxyHelper.IptablesSupported(client));
        Assert.Equal("-V", Assert.Single(fake.Calls).Arguments); Assert.True(fake.Calls[0].Process.IsDisposed);
    }
    [Theory]
    [InlineData("")] [InlineData("iptables version unknown")] [InlineData("error iptables v1.8.0")]
    [InlineData("iptables v1.8.0junk")] [InlineData("iptables v9999999999999.8.0")]
    public void MalformedBinaryVersionsAreErrors(string output)
    { using var client = Client(new ScriptedSystem { Respond = (_, _) => new(output) }); Assert.Throws<IpTablesNetException>(() => client.GetIptablesVersion()); }
    [Theory]
    [InlineData("3.11.99", false)] [InlineData("3.12", true)] [InlineData("3.12.0", true)]
    [InlineData("3.12.0-1-generic", true)] [InlineData("6.12.4-custom+debug\n", true)]
    [InlineData("6.12.4+", true)] [InlineData("3.11.0-999", false)] [InlineData("6.8.0-1018-azure", true)]
    [InlineData("invalid", false)] [InlineData("version 6.12.0", false)] [InlineData("99999999999999.1.0", false)]
    public void KernelVersionEligibilitySupportsDistroAndCustomReleases(string release, bool expected)
    {
        var fake = new ScriptedSystem { Respond = (_, _) => new(release) }; Assert.Equal(expected, SynProxyHelper.KernelSupported(fake));
        Assert.Equal("uname", Assert.Single(fake.Calls).Binary); Assert.Equal("-r", fake.Calls[0].Arguments);
    }
    [Fact]
    public void NonzeroExitIsNeverInterpretedAsSupported()
    {
        var fake = new ScriptedSystem { Respond = (_, _) => new("iptables v1.8.0", "permission denied", 2) };
        using var client = Client(fake); Assert.Throws<IpTablesNetException>(() => client.GetIptablesVersion());
        Assert.Contains("permission denied", Assert.Throws<IpTablesNetException>(() => SynProxyHelper.KernelSupported(fake)).Message);
        Assert.All(fake.Calls, x => Assert.True(x.Process.IsDisposed));
    }
}
