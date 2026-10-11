using System.Collections.Generic;
using System.Linq;
using IPTables.Net.IpSet;
using IPTables.Net.Iptables.DataTypes;
namespace IPTables.Net.Tests;
public class IpSetEntryIdentityTests
{
    [Fact]
    public void TimeoutDoesNotChangeKeyMembership()
    {
        var set = new IpSetSets(new[] { "create demo hash:ip", "add demo 192.0.2.1 timeout 10", "add demo 192.0.2.1 timeout 20" }, null).Sets.Single();
        var entry = Assert.Single(set.Entries);
        var equivalent = IpSetEntry.ParseFromParts(set, "192.0.2.1"); equivalent.Timeout = 99;
        var comparer = IpSetEntryKeyComparer.Instance;
        Assert.True(comparer.Equals(entry, equivalent)); Assert.Equal(comparer.GetHashCode(entry), comparer.GetHashCode(equivalent));
        Assert.True(set.Entries.Contains(equivalent));
        var map = new Dictionary<IpSetEntry, int>(comparer) { [entry] = 7 }; Assert.Equal(7, map[equivalent]);
        entry.Timeout = 30; Assert.True(set.Entries.Remove(equivalent)); Assert.Empty(set.Entries);
    }
    [Theory]
    [InlineData("192.0.2.1,tcp:80,198.51.100.2")]
    [InlineData("192.0.2.1,udp:80,198.51.100.1")]
    [InlineData("192.0.2.1,tcp:81,198.51.100.1")]
    [InlineData("192.0.2.2,tcp:80,198.51.100.1")]
    public void EveryTupleComponentParticipatesInIdentity(string other)
    {
        var set = new IpSetSets(new[] { "create demo hash:ip,port,ip" }, null).Sets.Single();
        var first = IpSetEntry.ParseFromParts(set, "192.0.2.1,tcp:80,198.51.100.1");
        var second = IpSetEntry.ParseFromParts(set, other);
        Assert.False(IpSetEntryKeyComparer.Instance.Equals(first, second));
        var entries = new HashSet<IpSetEntry>(IpSetEntryKeyComparer.Instance) { first, second }; Assert.Equal(2, entries.Count);
    }
    [Fact]
    public void ParsedAndConstructedCollectionsUseTheSameKeyRules()
    {
        var parsed = new IpSetSets(new[] { "create demo hash:ip", "add demo 192.0.2.1" }, null).Sets.Single();
        var constructed = new IpSetSet(parsed.Type, parsed.Name, 0, "inet", null, IpSetSyncMode.SetAndEntries);
        var one = new IpSetEntry(constructed, IpCidr.Parse("192.0.2.1"));
        constructed.Entries.Add(one);
        Assert.True(parsed.Entries.Contains(one));
        Assert.False(constructed.Entries.Add(IpSetEntry.ParseFromParts(constructed, "192.0.2.1")));
        var duplicate = IpSetEntry.ParseFromParts(constructed, "192.0.2.1");
        Assert.Equal(one, duplicate); Assert.Equal(one.GetHashCode(), duplicate.GetHashCode());
    }
}
