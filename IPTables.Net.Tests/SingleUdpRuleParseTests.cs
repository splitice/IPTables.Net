namespace IPTables.Net.Tests
{
    public class SingleUdpRuleParseTests
    {
        [Theory]
        [InlineData("-A INPUT -p udp -m udp --source-port 1000:2000", "-A INPUT -p udp -m udp --sport 1000:2000")]
        [InlineData("-A INPUT -p udp -m udp ! --source-port 1000:2000", "-A INPUT -p udp -m udp ! --sport 1000:2000")]
        [InlineData("-A INPUT -p udp -m udp --destination-port 53", "-A INPUT -p udp -m udp --dport 53")]
        [InlineData("-A INPUT -p udp -m udp ! --destination-port 53", "-A INPUT -p udp -m udp ! --dport 53")]
        public void TestUdpOptionRoundTrip(string input, string expected)
        {
            RuleParseAssert.RoundTrips(input, expected);
        }
    }
}
