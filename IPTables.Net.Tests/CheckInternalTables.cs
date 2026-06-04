using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables;

namespace IPTables.Net.Tests
{
    public class CheckInternalTables
    {
        [Fact]
        public void TestChains()
        {
            TestChain("filter", "INPUT");
            TestChain("filter", "FORWARD");
            TestChain("filter", "OUTPUT");

            TestChain("mangle", "INPUT");
            TestChain("mangle", "FORWARD");
            TestChain("mangle", "OUTPUT");
            TestChain("mangle", "PREROUTING");
            TestChain("mangle", "POSTROUTING");

            TestChain("nat", "PREROUTING");
            TestChain("nat", "POSTROUTING");
            TestChain("nat", "OUTPUT");

            TestChain("raw", "PREROUTING");
            TestChain("raw", "OUTPUT");
        }

        private void TestChain(string table, string chain)
        {
            Assert.True(IPTablesTables.IsInternalChain(table, chain), String.Format("{0}:{1} should be internal", table, chain));
        }
    }
}
