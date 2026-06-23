namespace IPTables.Net.Tests
{
    public class SingleStateRuleParseTests
    {
        [Theory]
        [InlineData("-A INPUT -m state --state ESTABLISHED")]
        [InlineData("-A INPUT -m state --state NEW")]
        [InlineData("-A INPUT -m state --state RELATED")]
        [InlineData("-A INPUT -m state --state INVALID")]
        [InlineData("-A INPUT -m state --state UNTRACKED")]
        public void TestStateOptionRoundTrip(string rule)
        {
            RuleParseAssert.RoundTrips(rule);
        }
    }
}
