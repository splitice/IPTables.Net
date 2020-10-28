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

            Assert.IsTrue(IpTablesRule.Parse(rule, null, chains, 4).Compare(IpTablesRule.Parse(rule, null, chains, 4)));
        }

        [Test]
        public void TestCompare2()
        {
            String rule = "-A AAAA -t raw -m hashlimit --hashlimit-name synflood_spoofe --hashlimit-above 111/second --hashlimit-burst 500 --hashlimit-mode dstip,dstport --hashlimit-srcmask 32 --hashlimit-dstmask 32 --hashlimit-htable-size 65000 --hashlimit-htable-max 30000 --hashlimit-htable-expire 6 --hashlimit-htable-gcinterval 600 -g AA";
            String rule2 = "-A AAAA -t raw -m hashlimit --hashlimit-above 111/sec --hashlimit-burst 500 --hashlimit-mode dstip,dstport --hashlimit-name synflood_spoofe --hashlimit-htable-size 65000 --hashlimit-htable-max 30000 --hashlimit-htable-gcinterval 600 --hashlimit-htable-expire 6 -g AA";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            Assert.IsTrue(IpTablesRule.Parse(rule, null, chains, 4).Compare(IpTablesRule.Parse(rule2, null, chains)));
        }

        [Test]
        public void TestCompare3()
        {
            String rule = "-A AAAA -t raw -m hashlimit --hashlimit-name X$a|b|c --hashlimit-above 111/second --hashlimit-burst 500 --hashlimit-mode dstport --hashlimit-srcmask 32 --hashlimit-dstmask 32 --hashlimit-htable-size 65000 --hashlimit-htable-max 30000 --hashlimit-htable-expire 6 --hashlimit-htable-gcinterval 600 -g AA";
            String rule2 = "-A AAAA -t raw -m hashlimit --hashlimit-above 111/sec --hashlimit-burst 500 --hashlimit-mode dstport --hashlimit-name 'X$a|b|c' --hashlimit-htable-size 65000 --hashlimit-htable-max 30000 --hashlimit-htable-gcinterval 600 --hashlimit-htable-expire 6 -g AA";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            Assert.IsTrue(IpTablesRule.Parse(rule, null, chains, 4).Compare(IpTablesRule.Parse(rule2, null, chains)));
        }

        [Test]
        public void TestCompare4()
        {
            String rule = "-A AAA -p udp -m hashlimit --hashlimit-upto 5000/sec --hashlimit-burst 10000 --hashlimit-mode dstport --hashlimit-name X|gm2nkFUEm3KMQelhNE9A --hashlimit-htable-size 32782 --hashlimit-htable-max 200000 --hashlimit-htable-expire 10000 -m comment --comment \"X|A|B\" -g aaaa";
            String rule2 = "-A AAA -p udp -g N_RE_gm2nkFUEm3KMQelhNE9A -m hashlimit --hashlimit-name 'X|gm2nkFUEm3KMQelhNE9A' --hashlimit-upto 5000/second --hashlimit-burst 10000 --hashlimit-mode dstport --hashlimit-srcmask 32 --hashlimit-dstmask 32 --hashlimit-htable-size 32782 --hashlimit-htable-max 200000 --hashlimit-htable-expire 10000 --hashlimit-htable-gcinterval 1000 -m comment --comment 'X|A|B' -g aaaa";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            Assert.IsTrue(IpTablesRule.Parse(rule, null, chains, 4).Compare(IpTablesRule.Parse(rule2, null, chains)));
        }

        [Test]
        public void TestByte1()
        {
            String rule = "-A ABC -m hashlimit --hashlimit-name aaaaaaaaaaaaaaaaaaaaaa --hashlimit-above 5kb/second --hashlimit-burst 500 --hashlimit-mode dstip,dstport --hashlimit-srcmask 32 --hashlimit-dstmask 32 --hashlimit-htable-size 65000 --hashlimit-htable-max 30000 --hashlimit-htable-expire 6 --hashlimit-htable-gcinterval 600 -j AVS";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            Assert.IsTrue(IpTablesRule.Parse(rule, null, chains, 4).Compare(IpTablesRule.Parse(rule, null, chains, 4)));
            Assert.IsTrue(IpTablesRule.Parse(rule, null, chains, 4).GetActionCommand().Contains("5kb/s"));
        }
        [Test]
        public void TestByte2()
        {
            String rule = "-A ABC -m hashlimit --hashlimit-name aaaaaaaaaaaaaaaaaaaaaa --hashlimit-above 5kb/second --hashlimit-burst 1mb --hashlimit-mode dstip,dstport --hashlimit-srcmask 32 --hashlimit-dstmask 32 --hashlimit-htable-size 65000 --hashlimit-htable-max 30000 --hashlimit-htable-expire 6 --hashlimit-htable-gcinterval 600 -j AVS";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            Assert.IsTrue(IpTablesRule.Parse(rule, null, chains, 4).Compare(IpTablesRule.Parse(rule, null, chains, 4)));
            Assert.IsTrue(IpTablesRule.Parse(rule, null, chains, 4).GetActionCommand().Contains("5kb/s"));
        }
        [Test]
        public void TestByte3()
        {
            String rule2 = "-A ABC -m hashlimit --hashlimit-above 1mb/s --hashlimit-burst 1500kb --hashlimit-mode dstip --hashlimit-name r";
            String rule = "-A ABC -m hashlimit --hashlimit-name r --hashlimit-above 1mb/s --hashlimit-burst 1mb --hashlimit-mode dstip --hashlimit-srcmask 32 --hashlimit-dstmask 32 --hashlimit-htable-size 65000 --hashlimit-htable-max 200000 --hashlimit-htable-expire 10000 --hashlimit-htable-gcinterval 1000";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            var r1 = IpTablesRule.Parse(rule, null, chains, 4);
            var r2 = IpTablesRule.Parse(rule2, null, chains, 4);
            Assert.IsTrue(r1.Compare(r2));
        }


        [Test]
        public void TestByte4()
        {
            String rule2 = "-A ABC -m hashlimit --hashlimit-name C_82 --hashlimit-above 10kb/second --hashlimit-burst 10kb --hashlimit-mode srcip,dstip --hashlimit-srcmask 32 --hashlimit-dstmask 32 --hashlimit-htable-size 16000 --hashlimit-htable-max 256000 --hashlimit-htable-expire 10000 --hashlimit-htable-gcinterval 1000";
            String rule = "-A ABC -m hashlimit --hashlimit-above 10kb/s --hashlimit-burst 10kb --hashlimit-mode srcip,dstip --hashlimit-name C_82 --hashlimit-htable-size 16000 --hashlimit-htable-max 256000 --hashlimit-htable-expire 10000";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            var r1 = IpTablesRule.Parse(rule, null, chains, 4);
            var r2 = IpTablesRule.Parse(rule2, null, chains, 4);
            Assert.IsTrue(r1.Compare(r2));
        }
    }
}