namespace IPTables.Net.Tests
{
    public class SingleTProxyRuleParseTests
    {
        [Theory]
        [InlineData("-A PREROUTING -t mangle -j TPROXY --on-port 8080", "-A PREROUTING -t mangle -j TPROXY --on-port 8080 --on-ip 0.0.0.0")]
        [InlineData("-A PREROUTING -t mangle -j TPROXY --on-ip 127.0.0.1", "-A PREROUTING -t mangle -j TPROXY --on-port 0 --on-ip 127.0.0.1")]
        [InlineData("-A PREROUTING -t mangle -j TPROXY --tproxy-mark 0x1/0xFF", "-A PREROUTING -t mangle -j TPROXY --on-port 0 --on-ip 0.0.0.0 --tproxy-mark 0x1/0xFF")]
        [InlineData("-A PREROUTING -t mangle -j TPROXY --on-port 8080 --on-ip 127.0.0.1 --tproxy-mark 0x1/0xFF", "-A PREROUTING -t mangle -j TPROXY --on-port 8080 --on-ip 127.0.0.1 --tproxy-mark 0x1/0xFF")]
        public void TestTProxyOptionRoundTrip(string input, string expected)
        {
            RuleParseAssert.RoundTrips(input, expected);
        }
    }
}
