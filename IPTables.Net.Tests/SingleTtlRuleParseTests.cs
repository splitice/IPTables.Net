namespace IPTables.Net.Tests
{
    public class SingleTtlRuleParseTests
    {
        [Fact]
        public void TestTtlIncrementRoundTrip()
        {
            RuleParseAssert.RoundTrips("-A PREROUTING -t mangle -j TTL --ttl-inc 1");
        }
    }
}
