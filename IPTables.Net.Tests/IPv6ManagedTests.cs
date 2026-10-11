using System.Linq;
using System.Net;
using IPTables.Net.Exceptions;
using IPTables.Net.IpSet;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Adapter;
using IPTables.Net.Iptables.Adapter.Client.Helper;
using IPTables.Net.Iptables.DataTypes;
using IPTables.Net.Iptables.Modules.Core;
namespace IPTables.Net.Tests;
public class IPv6ManagedTests
{
    [Theory]
    [InlineData("::/0")] [InlineData("::1")] [InlineData("2001:db8::/64")] [InlineData("2001:db8::1")]
    public void CoreTcpAndUdpRoundTripWithVersionAndFields(string address)
    {
        foreach (var protocol in new[] { "tcp", "udp" })
        {
            var text = $"-A INPUT -p {protocol} -s {address} -j ACCEPT -m {protocol} --dport 443";
            var rule = RuleParseAssert.RoundTrips(text, version: 6);
            Assert.Equal(6, rule.IpVersion); Assert.Equal(IpCidr.Parse(address), rule.GetModule<CoreModule>("core").Source.Value);
            var saved = IPTablesSaveParser.GetRulesFromOutput(null, "*filter\n:INPUT ACCEPT [0:0]\n" + text + "\nCOMMIT", "filter", 6);
            Assert.Equal(text, Assert.Single(saved.GetChain("INPUT", "filter").Rules).GetActionCommand());
        }
    }
    [Theory]
    [InlineData("[2001:db8::1]:80-90")] [InlineData("[2001:db8::1]-[2001:db8::2]:443")]
    [InlineData("2001:db8::1")]
    public void NatRangesAndAddressFields(string range)
    {
        RuleParseAssert.RoundTrips("-A PREROUTING -t nat -j DNAT --to-destination " + range, version: 6);
        var parsed = IPPortOrRange.Parse(range); Assert.Equal(IPAddress.Parse("2001:db8::1"), parsed.LowerAddress);
        Assert.Equal(range, parsed.ToString());
    }
    [Fact]
    public void FamiliesAreValidatedAndFactoriesSelectIpv6Executables()
    {
        Assert.Throws<IpTablesParserException>(() => IpTablesRule.Parse("-A INPUT -s 192.0.2.1", null, new IpTablesChainSet(6), 6));
        var os = new ScriptedSystem { Respond = (_, _) => new("*filter\nCOMMIT") };
        using var binary = new IpTablesSystem(os, new IPTablesBinaryAdapter()).GetTableAdapter(6);
        binary.AddRule("-A INPUT -j ACCEPT"); binary.ListRules("filter");
        using var restore = new IpTablesSystem(os, new IPTablesRestoreAdapter()).GetTableAdapter(6);
        restore.ListRules("filter"); restore.StartTransaction(); restore.AddRule("-A INPUT -j ACCEPT"); restore.EndTransactionCommit();
        Assert.Equal(new[] { "ip6tables", "ip6tables-save", "ip6tables-save", "ip6tables-restore" }, os.Calls.Select(c => c.Binary));
    }
    [Fact]
    public void Ipv6SetTuplesConvergeWithoutCommands()
    {
        const string saved = "create demo hash:ip,port,ip family inet6\nadd demo 2001:db8::1,tcp:443,2001:db8::2\n";
        var os = new ScriptedSystem { Respond = (_, _) => new(saved) };
        var system = new IpTablesSystem(os, null); var sets = new IpSetSets(saved.Split('\n').Where(x => x.Length != 0), system);
        Assert.Equal("inet6", sets.Sets.Single().Family);
        Assert.Equal(IPAddress.Parse("2001:db8::2"), sets.Sets.Single().Entries.Single().Cidr2.Address);
        sets.Sync(); Assert.Single(os.Calls); Assert.Equal("save", os.Calls[0].Arguments);
    }
}
