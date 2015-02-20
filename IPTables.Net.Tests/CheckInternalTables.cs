using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    class CheckInternalTables
    {
        [Test]
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
            Assert.IsTrue(IPTablesTables.IsInternalChain(table, chain));
        }
    }
}
