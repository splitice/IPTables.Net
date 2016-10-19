using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleHashrouteTests
    {
        [Test]
        public void TestCompare1()
        {
            String rule = "-A ABC -m hashroute --hashroute-name aaaaaaaaaaaaaaaaaaaaaa --hashroute-mode dstip,dstport --hashroute-srcmask 32 --hashroute-dstmask 32 --hashroute-htable-size 65000 --hashroute-htable-max 30000 --hashroute-htable-expire 6 --hashroute-htable-gcinterval 600 -j AVS";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            Assert.AreEqual(IpTablesRule.Parse(rule, null, chains, 4), IpTablesRule.Parse(rule, null, chains, 4));
        }

        [Test]
        public void TestCompare2()
        {
            String rule = "-A AAAA -t raw -m hashroute --hashroute-name synflood_spoofe --hashroute-mode dstip,dstport --hashroute-srcmask 32 --hashroute-dstmask 32 --hashroute-htable-size 65000 --hashroute-htable-max 30000 --hashroute-htable-expire 6 --hashroute-htable-gcinterval 600 -g AA";
            String rule2 = "-A AAAA -t raw -m hashroute --hashroute-mode dstip,dstport --hashroute-name synflood_spoofe --hashroute-htable-size 65000 --hashroute-htable-max 30000 --hashroute-htable-gcinterval 600 --hashroute-htable-expire 6 -g AA";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            Assert.AreEqual(IpTablesRule.Parse(rule, null, chains, 4), IpTablesRule.Parse(rule2, null, chains));
        }
        [Test]
        public void TestCompareTarget1()
        {
            String rule = "-A ABC -j HASHROUTE --hashroute-name aaaaaaaaaaaaaaaaaaaaaa --hashroute-mode dstip,dstport --hashroute-srcmask 32 --hashroute-dstmask 32 --hashroute-htable-size 65000 --hashroute-htable-max 30000 --hashroute-htable-expire 6 --hashroute-htable-gcinterval 600 -j AVS";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            Assert.AreEqual(IpTablesRule.Parse(rule, null, chains, 4), IpTablesRule.Parse(rule, null, chains, 4));
            Assert.IsFalse(IpTablesRule.Parse(rule, null, chains, 4).ToString().Contains("-m HASHROUTE"));
        }

        [Test]
        public void TestCompareTarget2()
        {
            String rule = "-A AAAA -t raw -j HASHROUTE --hashroute-name synflood_spoofe --hashroute-mode dstip,dstport --hashroute-srcmask 32 --hashroute-dstmask 32 --hashroute-htable-size 65000 --hashroute-htable-max 30000 --hashroute-htable-expire 6 --hashroute-htable-gcinterval 600 -g AA";
            String rule2 = "-A AAAA -t raw -j HASHROUTE --hashroute-mode dstip,dstport --hashroute-name synflood_spoofe --hashroute-htable-size 65000 --hashroute-htable-max 30000 --hashroute-htable-gcinterval 600 --hashroute-htable-expire 6 -g AA";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            Assert.AreEqual(IpTablesRule.Parse(rule, null, chains, 4), IpTablesRule.Parse(rule2, null, chains));
            Assert.IsFalse(IpTablesRule.Parse(rule, null, chains, 4).ToString().Contains("-m HASHROUTE"));
        }
    }
}