namespace IPTables.Net.Tests
{
    public class SingleDynjmpRuleParseTests
    {
        [Theory]
        [InlineData("-A INPUT -j DYNJMP")]
        [InlineData("-A INPUT -j SYNJMP")]
        public void TestNoOptionDynjmpTargetsRoundTrip(string rule)
        {
            RuleParseAssert.RoundTrips(rule);
        }
    }
}
