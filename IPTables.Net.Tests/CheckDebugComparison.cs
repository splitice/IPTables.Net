using IPTables.Net.Iptables.Modules.HashLimit;
using System;
using System.Linq;
using IPTables.Net.Iptables;
using static IPTables.Net.Iptables.IpTablesRule;

namespace IPTables.Net.Tests
{
    public class CheckDebugComparison
    {
        [Fact]
        public void TestHashLimitMemberProperties()
        {
            var hl = new HashLimitModule(4);
            var properties = IpTablesRule.DebugComparison.GetModuleProperties(hl).ToList();
            Assert.Contains("Name", properties);
        }
    }
}
