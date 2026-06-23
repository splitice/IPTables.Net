namespace IPTables.Net.Tests
{
    public class SingleSocketRuleParseTests
    {
        [Fact]
        public void TestSocketTransparentRoundTrip()
        {
            RuleParseAssert.RoundTrips("-A INPUT -m socket --transparent");
        }
    }
}
