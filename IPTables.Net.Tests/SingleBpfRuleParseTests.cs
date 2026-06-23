namespace IPTables.Net.Tests
{
    public class SingleBpfRuleParseTests
    {
        [Fact]
        public void TestBpfBytecodeRoundTrip()
        {
            RuleParseAssert.RoundTrips("-A INPUT -m bpf --bytecode 1,6,0,0,262144");
        }
    }
}
