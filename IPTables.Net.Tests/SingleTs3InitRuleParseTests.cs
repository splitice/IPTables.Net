namespace IPTables.Net.Tests
{
    public class SingleTs3InitRuleParseTests
    {
        [Theory]
        [InlineData("-A INPUT -j TS3INIT_GET_COOKIE")]
        [InlineData("-A INPUT -j TS3INIT_RESET")]
        [InlineData("-A INPUT -j TS3INIT_SET_COOKIE --random-seed abc")]
        [InlineData("-A INPUT -m ts3init_get_cookie --min-client 5 --check-time 10")]
        [InlineData("-A INPUT -m ts3init_get_puzzle --random-seed abc --min-client 5 --check-cookie")]
        public void TestTs3InitOptionRoundTrip(string rule)
        {
            RuleParseAssert.RoundTrips(rule);
        }
    }
}
