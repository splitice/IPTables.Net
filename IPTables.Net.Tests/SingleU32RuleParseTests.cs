namespace IPTables.Net.Tests
{
    public class SingleU32RuleParseTests
    {
        [Fact]
        public void TestU32OptionRoundTrip()
        {
            RuleParseAssert.RoundTrips(
                "-A INPUT -m u32 --u32 '0&0xFFFF=0x100:0xFFFF'",
                "-A INPUT -m u32 --u32 '0&65535=256:65535'");
        }
    }
}
