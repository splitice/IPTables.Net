namespace IPTables.Net.Tests
{
    public class SingleDevgroupRuleParseTests
    {
        [Theory]
        [InlineData("-A INPUT -m devgroup --src-group 0x1/0xFF")]
        [InlineData("-A INPUT -m devgroup ! --src-group 0x1/0xFF")]
        [InlineData("-A INPUT -m devgroup --dst-group 0x2/0xFF")]
        [InlineData("-A INPUT -m devgroup ! --dst-group 0x2/0xFF")]
        [InlineData("-A INPUT -m devgroup --src-group 0x1/0xFF --dst-group 0x2/0xFF")]
        public void TestDevgroupOptionRoundTrip(string rule)
        {
            RuleParseAssert.RoundTrips(rule);
        }
    }
}
