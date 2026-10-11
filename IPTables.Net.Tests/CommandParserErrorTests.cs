using IPTables.Net.Exceptions;
using IPTables.Net.Iptables;
namespace IPTables.Net.Tests;
public class CommandParserErrorTests
{
    [Theory]
    [InlineData("")] [InlineData(" \t ")] [InlineData("-A")] [InlineData("-A INPUT -m")]
    [InlineData("-A INPUT -j")] [InlineData("-A INPUT -t")] [InlineData("-A INPUT -m tcp --dport")]
    [InlineData("-A INPUT --unknown")]
    [InlineData("-A INPUT ! ! -p tcp")] [InlineData("-A INPUT !")]
    [InlineData("-A INPUT -m tcp --dport nope")] [InlineData("-A INPUT -m comment --comment 'bad")]
    [InlineData("-R INPUT")] [InlineData("-D INPUT")]
    [InlineData("-R INPUT 0 -j ACCEPT")] [InlineData("-R INPUT -1 -j ACCEPT")]
    [InlineData("-R INPUT 4294967295 -j ACCEPT")]
    public void InvalidCommandsHaveContextAndDoNotMutateChains(string input)
    {
        var chains = new IpTablesChainSet(4);
        Assert.Contains(input, Assert.Throws<IpTablesParserException>(() => IpTablesCommand.Parse(input, null, chains)).Message);
        Assert.Empty(chains.Chains);
    }
    [Fact]
    public void UnknownModulesRemainSupportedThroughPolyfill()
    { RuleParseAssert.RoundTrips("-A INPUT -m missing"); }

    [Theory]
    [InlineData("-D INPUT 1", 0)] [InlineData("-R INPUT 2 -j ACCEPT", 1)]
    [InlineData("-I INPUT -j ACCEPT", -1)] [InlineData("-I INPUT", -1)]
    public void ValidOffsets(string input, int offset)
    { Assert.Equal(offset, IpTablesCommand.Parse(input, null, new IpTablesChainSet(4)).Offset); }
}
