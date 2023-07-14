using IPTables.Net.Iptables.Modules.HashLimit;
using NUnit.Framework;
using System;
using System.Linq;
using IPTables.Net.Iptables;
using static IPTables.Net.Iptables.IpTablesRule;

namespace IPTables.Net.Tests
{
    [TestFixture]
    public class CheckDebugComparison
    {
        [TestCase]
        public void TestHashLimitMemberProperties()
        {
            var hl = new HashLimitModule(4);
            var properties = IpTablesRule.DebugComparison.GetModuleProperties(hl).ToList();
            Assert.Contains("Name", properties);
        }
    }
}
