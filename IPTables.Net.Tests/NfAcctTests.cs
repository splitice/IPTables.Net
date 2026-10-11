using System;
using System.Linq;
using IPTables.Net.Exceptions;
namespace IPTables.Net.Tests;
public class NfAcctTests
{
    private const string Xml = "<nfacct><obj><name>alpha</name><pkts>7</pkts><bytes>900</bytes></obj><obj><name>beta</name><pkts>18446744073709551615</pkts><bytes>10</bytes></obj></nfacct>";
    [Fact]
    public void GetAndListAgreeOnCountersAndMissingNames()
    {
        var fake = new ScriptedSystem { Respond = (_, _) => new(Xml) }; var client = new NfAcct.NfAcct(fake);
        var first = client.Get("alpha"); var all = client.List();
        Assert.Equal(900ul, first.Bytes); Assert.Equal(7ul, first.Packets);
        Assert.Equal(first.Bytes, all[0].Bytes); Assert.Equal(first.Packets, all[0].Packets);
        Assert.Equal(ulong.MaxValue, all[1].Packets); Assert.Null(client.Get("missing"));
        Assert.True(client.Exist("alpha")); Assert.False(client.Exist("missing"));
    }
    [Fact]
    public void CommandsResetAndEscapeNames()
    {
        var fake = new ScriptedSystem(); var client = new NfAcct.NfAcct(fake);
        Assert.Null(client.Get("a b", true)); Assert.Empty(client.List(true)); client.Add("a b"); client.Delete("a\"b");
        Assert.Equal(new[] { "get \"a b\" xml reset", "list xml reset", "add \"a b\"", "del \"a\\\"b\"" }, fake.Calls.Select(x => x.Arguments));
        Assert.All(fake.Calls, call => { Assert.Equal("/usr/sbin/nfacct", call.Binary); Assert.True(call.Process.IsDisposed); });
    }
    [Theory]
    [InlineData("<broken>")] [InlineData("<nfacct><obj/></nfacct>")]
    [InlineData("<nfacct><obj><name>a</name><pkts>-1</pkts><bytes>0</bytes></obj></nfacct>")]
    [InlineData("<nfacct><obj><name>a</name><pkts>1</pkts><bytes>18446744073709551616</bytes></obj></nfacct>")]
    public void MalformedObjectsFailConsistently(string output)
    {
        var client = new NfAcct.NfAcct(new ScriptedSystem { Respond = (_, _) => new(output) });
        Assert.Throws<FormatException>(() => client.Get("a")); Assert.Throws<FormatException>(() => client.List());
    }
    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(3)] [InlineData(4)]
    public void EveryCommandReportsNonzeroExit(int operation)
    {
        var fake = new ScriptedSystem { Respond = (_, _) => new("partial", "denied", 2) }; var client = new NfAcct.NfAcct(fake);
        Action[] actions = { () => client.Get("a"), () => client.List(), () => client.Add("a"), () => client.Delete("a"), () => client.Exist("a") };
        Assert.Contains("denied", Assert.Throws<IpTablesNetException>(actions[operation]).Message);
        Assert.True(Assert.Single(fake.Calls).Process.IsDisposed);
    }
}
