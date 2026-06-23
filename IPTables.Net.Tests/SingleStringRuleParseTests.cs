namespace IPTables.Net.Tests
{
    public class SingleStringRuleParseTests
    {
        [Theory]
        [InlineData("-A INPUT -m string --algo bm --from 1 --to 10 --string test", "-A INPUT -m string --algo bm --from 1 --to 10 --string test")]
        [InlineData("-A INPUT -m string --algo kmp --string test", "-A INPUT -m string --algo kmp --string test")]
        [InlineData("-A INPUT -m string --algo bm ! --string test", "-A INPUT -m string --algo bm ! --string test")]
        [InlineData("-A INPUT -m string --algo bm --hex-string '|41 42|'", "-A INPUT -m string --algo bm --hex-string '|4142|'")]
        public void TestStringOptionRoundTrip(string input, string expected)
        {
            RuleParseAssert.RoundTrips(input, expected);
        }
    }
}
