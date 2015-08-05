using System;
using IPTables.Net.Iptables;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class SingleHashlimitRuleParseTests
    {
        [Test]
        public void TestCompare1()
        {
            String rule = "-A ABC -m hashlimit --hashlimit-name aaaaaaaaaaaaaaaaaaaaaa --hashlimit-above 125/second --hashlimit-burst 500 --hashlimit-mode dstip,dstport --hashlimit-srcmask 32 --hashlimit-dstmask 32 --hashlimit-htable-size 65000 --hashlimit-htable-max 30000 --hashlimit-htable-expire 6 --hashlimit-htable-gcinterval 600 -j AVS";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            Assert.AreEqual(IpTablesRule.Parse(rule, null, chains), IpTablesRule.Parse(rule, null, chains));
        }

        [Test]
        public void TestCompare2()
        {
            String rule = "-A AAAA -t raw -m hashlimit --hashlimit-name synflood_spoofe --hashlimit-above 111/second --hashlimit-burst 500 --hashlimit-mode dstip,dstport --hashlimit-srcmask 32 --hashlimit-dstmask 32 --hashlimit-htable-size 65000 --hashlimit-htable-max 30000 --hashlimit-htable-expire 6 --hashlimit-htable-gcinterval 600 -g AA";
            String rule2 = "-A AAAA -t raw -m hashlimit --hashlimit-above 111/sec --hashlimit-burst 500 --hashlimit-mode dstip,dstport --hashlimit-name synflood_spoofe --hashlimit-htable-size 65000 --hashlimit-htable-max 30000 --hashlimit-htable-gcinterval 600 --hashlimit-htable-expire 6 -g AA";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            Assert.AreEqual(IpTablesRule.Parse(rule, null, chains), IpTablesRule.Parse(rule2, null, chains));
        }
    }
}