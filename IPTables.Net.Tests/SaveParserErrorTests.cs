using System.Linq;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.Adapter.Client.Helper;
namespace IPTables.Net.Tests;
public class SaveParserErrorTests
{
    [Theory]
    [InlineData("")] [InlineData("COMMIT")] [InlineData("*filter\n:INPUT ACCEPT [0:0]")]
    [InlineData("*nat\nCOMMIT")] [InlineData("*nat\n*filter\nCOMMIT")]
    [InlineData("*filter\n[12 -A INPUT -j ACCEPT\nCOMMIT")]
    [InlineData("*filter\n[a:2] -A INPUT -j ACCEPT\nCOMMIT")]
    [InlineData("*filter\n[1:2:3] -A INPUT -j ACCEPT\nCOMMIT")]
    [InlineData("*filter\n[9223372036854775808:2] -A INPUT -j ACCEPT\nCOMMIT")]
    public void MalformedDumpsAreNotEmptyTables(string input)
    { Assert.Throws<IpTablesNetException>(() => IPTablesSaveParser.GetRulesFromOutput(null, input, "filter", 4)); }
    [Theory]
    [InlineData("")] [InlineData("[1:2] ")]
    public void RecoveryIsConsistentForCounterAndPlainRules(string prefix)
    {
        var input = "*filter\n:INPUT ACCEPT [0:0]\n" + prefix + "-A INPUT --invalid\n-A INPUT -j ACCEPT\nCOMMIT";
        Assert.ThrowsAny<IpTablesNetException>(() => IPTablesSaveParser.GetRulesFromOutput(null, input, "filter", 4));
        var parsed = IPTablesSaveParser.GetRulesFromOutput(null, input, "filter", 4, true);
        Assert.Equal("-A INPUT -j ACCEPT", Assert.Single(parsed.GetChain("INPUT", "filter").Rules).GetActionCommand());
    }
    [Fact]
    public void RequestedTableHasIndependentChainsOrderAndLargeCounters()
    {
        const string input = "# header\r\n*nat\r\n:OTHER - [0:0]\r\nCOMMIT\r\n\r\n*filter\r\n:INPUT ACCEPT [0:0]\r\n[12:9223372036854775807] -A INPUT -j ACCEPT\r\n-A INPUT -j DROP\r\nCOMMIT";
        var result = IPTablesSaveParser.GetRulesFromOutput(null, input, "filter", 4);
        var chain = Assert.Single(result.Chains); Assert.Equal("INPUT", chain.Name);
        Assert.Equal(new[] { "-A INPUT -j ACCEPT", "-A INPUT -j DROP" }, chain.Rules.Select(r => r.GetActionCommand()));
        Assert.Equal(long.MaxValue, chain.Rules[0].Counters.Bytes); Assert.Equal(12, chain.Rules[0].Counters.Packets);
        Assert.Empty(IPTablesSaveParser.GetRulesFromOutput(null, "*filter\nCOMMIT", "filter", 4).Chains);
    }
}
