using IPTables.Net.Iptables;

namespace IPTables.Net.Tests
{
    internal static class RuleParseAssert
    {
        public static IpTablesRule RoundTrips(string input, string expected = null, int version = 4)
        {
            expected = expected ?? input;

            var rule = IpTablesRule.Parse(input, null, new IpTablesChainSet(version), version);
            Assert.Equal(expected, rule.GetActionCommand());

            var reparsed = IpTablesRule.Parse(expected, null, new IpTablesChainSet(version), version);
            Assert.True(reparsed.Compare(rule), "Rendered rule should parse back to the same model: " + expected);
            Assert.Equal(expected, reparsed.GetActionCommand());

            return rule;
        }
    }
}
