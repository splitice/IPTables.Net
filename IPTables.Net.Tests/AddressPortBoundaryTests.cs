using System;
using System.Net;
using System.Numerics;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.DataTypes;
namespace IPTables.Net.Tests;
public class AddressPortBoundaryTests
{
    [Theory]
    [InlineData("192.0.2.129/24", "192.0.2.0", "192.0.2.255", "192.0.3.0", 256)]
    [InlineData("2001:db8::81/120", "2001:db8::", "2001:db8::ff", "2001:db8::100", 256)]
    public void NetworkBoundariesAndRebase(string text, string start, string end, string outside, int count)
    {
        var cidr = IpCidr.Parse(text); Assert.Equal(new BigInteger(count), cidr.Addresses);
        Assert.True(cidr.Contains(IPAddress.Parse(start))); Assert.True(cidr.Contains(IPAddress.Parse(end))); Assert.False(cidr.Contains(IPAddress.Parse(outside)));
        Assert.True(cidr.Contains(IpCidr.Parse(end))); Assert.False(IpCidr.Parse(end).Contains(cidr));
        Assert.Equal(IPAddress.Parse(start), IpCidr.NewRebase(cidr.Address, cidr.Prefix).Address);
        Assert.True(IpCidr.Parse(start).CompareTo(IpCidr.Parse(end)) < 0);
    }
    [Theory]
    [InlineData("0.0.0.0/0", 32)] [InlineData("::/0", 128)] [InlineData("0.0.0.0/32", 0)] [InlineData("::1/128", 0)]
    public void ZeroAndHostPrefixesPreserveCounts(string text, int power)
    { var value = IpCidr.Parse(text); Assert.Equal(BigInteger.Pow(2, power), value.Addresses); Assert.Equal(value, IpCidr.Parse(value.ToString())); }
    [Theory]
    [InlineData("0.0.0.0/33")] [InlineData("1.2.3.4/-1")] [InlineData("::/129")] [InlineData("::/4294967296")]
    [InlineData("1.2.3.4/24/1")] [InlineData("1.2.3.4/")]
    public void InvalidPrefixesFail(string text) => Assert.Throws<IpTablesNetException>(() => IpCidr.Parse(text));
    [Fact]
    public void FamiliesNeverContainOneAnotherAndRebaseValidatesPrefix()
    {
        Assert.False(IpCidr.Parse("0.0.0.0/0").Contains(IPAddress.IPv6Loopback));
        Assert.False(IpCidr.Parse("::/0").Contains(IpCidr.Any));
        Assert.Throws<ArgumentOutOfRangeException>(() => IpCidr.NewRebase(IPAddress.Any, 33));
        Assert.Equal(24u, IpCidr.Parse("0.0.0.0/24").Prefix);
    }
    [Theory]
    [InlineData("0")] [InlineData("65535")] [InlineData("65536")] [InlineData("4294967295")] [InlineData("0:65536")]
    public void GenericNumericRangesAreNotLimitedToPorts(string text) => Assert.Equal(text, PortOrRange.Parse(text, ':').ToString());
    [Theory]
    [InlineData("2:1")] [InlineData(":1")] [InlineData("1:")] [InlineData("1:2:3")] [InlineData("4294967296")]
    public void InvalidNumericRangesFail(string text) => Assert.ThrowsAny<Exception>(() => PortOrRange.Parse(text, ':'));
    [Theory]
    [InlineData("192.0.2.1:65535")] [InlineData("192.0.2.1-192.0.2.2:80-90")]
    [InlineData("[2001:db8::1]:80")] [InlineData("[2001:db8::1]-[2001:db8::2]:80-90")]
    [InlineData("2001:db8::1")] [InlineData("192.0.2.1")]
    public void AddressRangesRoundTrip(string text)
    { var parsed = IPPortOrRange.Parse(text); Assert.Equal(text, parsed.ToString()); Assert.Equal(parsed.Port, IPPortOrRange.Parse(parsed.ToString()).Port); }
    [Theory]
    [InlineData("192.0.2.1:65536")] [InlineData("192.0.2.2-192.0.2.1")]
    [InlineData("[::1]:90-80")] [InlineData("999.1.1.1")]
    public void InvalidAddressRangesFail(string text) => Assert.ThrowsAny<Exception>(() => IPPortOrRange.Parse(text));
    [Fact]
    public void LegacySingleEndpointFallbackAndIpv6Rendering()
    {
        foreach (var invalid in new[] { "bad", "192.0.2.1:65536", "192.0.2.1:abc", "192.0.2.1:1:2" }) Assert.Equal(IpPort.Any, IpPort.Parse(invalid));
        Assert.Equal("[::1]:80", IpPort.Parse("[::1]:80").ToString());
        Assert.Equal("192.0.2.1:0", IpPort.Parse("192.0.2.1").ToString());
    }
    [Theory]
    [InlineData("fe80::1234%7", 128u, "fe80::1234%7")]
    [InlineData("fe80::1234%7", 64u, "fe80::%7")]
    [InlineData("2001:db8::1234", 64u, "2001:db8::")]
    [InlineData("192.0.2.129", 32u, "192.0.2.129")]
    [InlineData("192.0.2.129", 24u, "192.0.2.0")]
    public void RebasePreservesScopeAndAddressFamily(string original, uint prefix, string expected)
    {
        var address = IPAddress.Parse(original);
        var result = IpCidr.NewRebase(address, prefix);
        Assert.Equal(IPAddress.Parse(expected), result.Address);
        Assert.Equal(prefix, result.Prefix);
        Assert.Equal(address.AddressFamily, result.Address.AddressFamily);
        Assert.Equal(original, address.ToString());
        if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            Assert.Equal(address.ScopeId, result.Address.ScopeId);
    }
}
