using System;
using System.Linq;
using IPTables.Net.Exceptions;
using IPTables.Net.IpSet;
namespace IPTables.Net.Tests;
public class IpSetParserFidelityTests
{
    [Fact]
    public void SetAndEntryMetadataSurviveRoundTrip()
    {
        var set = IpSetSet.Parse("demo hash:ip,port,ip bucketsize 8 initval 0x10 timeout 60 counters", null);
        var copy = IpSetSet.Parse(set.GetCommand(), null);
        Assert.Equal(8, copy.BucketSize); Assert.Equal(16u, copy.InitVal); Assert.Equal(60, copy.Timeout); Assert.Contains("counters", copy.CreateOptions);
        var sets = new IpSetSets(null); sets.AddSet(copy);
        var entry = IpSetEntry.Parse("demo 192.0.2.1,TCP:80,198.51.100.1 timeout 10 packets 7 bytes 900", sets);
        Assert.Equal("192.0.2.1,tcp:80,198.51.100.1", entry.GetKeyCommand());
        Assert.Equal("add demo 192.0.2.1,tcp:80,198.51.100.1 timeout 10", Assert.Single(copy.GetEntryCommands()));
    }
    [Theory]
    [InlineData("demo")] [InlineData("unknown 192.0.2.1,tcp:80")]
    [InlineData("demo 192.0.2.1")] [InlineData("demo 192.0.2.1,tcp:80,extra")]
    [InlineData("demo 192.0.2.1,tcp:99999")] [InlineData("demo 192.0.2.1,tcp:80 timeout")]
    [InlineData("demo 192.0.2.1,tcp:80 packets bad")] [InlineData("demo 192.0.2.1,tcp:80 unexpected")]
    public void InvalidEntriesNeverLeavePartialMembers(string command)
    {
        var sets = new IpSetSets(new[] { "create demo hash:ip,port" }, null);
        Assert.Throws<IpTablesNetException>(() => IpSetEntry.Parse(command, sets));
        Assert.Empty(sets.Sets.Single().Entries);
    }
    [Theory]
    [InlineData("demo")] [InlineData("demo hash")]
    [InlineData("demo hash:ip timeout")] [InlineData("demo hash:ip,mac")]
    public void IncompleteAndUnsupportedSetTypesAreRejected(string command)
    { Assert.Throws<IpTablesNetException>(() => IpSetSet.Parse(command, null)); }
}
