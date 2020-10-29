using IPTables.Net.Iptables.Modules.HashLimit;
using NUnit.Framework;
using System;
using System.Linq;
using static IPTables.Net.Iptables.IpTablesRule;

namespace IPTables.Net.Tests
{
    [TestFixture]
    public class CheckDebugComparison
    {
        [TestCase]
        public void TestHashLimitMemberProperties()
        {
            var compare = new DebugComparison();
            var hl = new HashLimitModule(4);
            var properties = compare.GetModuleProperties(hl).ToList();
            Assert.Contains("Name", properties);
        }
    }
}
