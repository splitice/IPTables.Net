using System.Collections.Generic;
using IPTables.Net.IpUtils.Utils;
namespace IPTables.Net.Tests;
public class IpObjectTests
{
    [Fact]
    public void IdentityIgnoresInsertionOrderAndIncludesValuesAndFlags()
    {
        var a = new IpObject { Pairs = new() { ["to"] = "default", ["dev"] = "eth0" }, Singles = new() { "onlink", "linkdown" } };
        var b = new IpObject { Pairs = new() { ["dev"] = "eth0", ["to"] = "default" }, Singles = new() { "linkdown", "onlink" } };
        Assert.Equal(a, b); Assert.Equal(a.GetHashCode(), b.GetHashCode()); Assert.Contains(b, new HashSet<IpObject> { a });
        b.Pairs["dev"] = "eth1"; Assert.NotEqual(a, b);
        b.Pairs["dev"] = "eth0"; b.Singles.Remove("onlink"); Assert.NotEqual(a, b); Assert.False(a.Equals(null));
    }
    [Fact]
    public void CloneOwnsBothCollections()
    {
        var source = new IpObject { Pairs = new() { ["dev"] = "eth0" }, Singles = new() { "onlink" } }; var clone = source.Clone();
        Assert.Equal(source, clone); Assert.NotSame(source.Pairs, clone.Pairs); Assert.NotSame(source.Singles, clone.Singles);
        clone.Pairs["dev"] = "eth1"; clone.Singles.Clear();
        Assert.Equal("eth0", source.Pairs["dev"]); Assert.Contains("onlink", source.Singles);
    }
}
