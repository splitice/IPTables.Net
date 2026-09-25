using System;
using System.Security.Cryptography;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Modules.Mark;

namespace IPTables.Net.Tests
{
    public class IPTablesRuleTests
    {
        [Fact]
        public void TestDefaultChain()
        {
            IpTablesChainSet chains = new IpTablesChainSet(4);
            var rule = IpTablesRule.Parse("-A PREROUTING -s 1.1.1.1 -j TEST", null, chains, 4, "raw", IpTablesRule.ChainCreateMode.CreateNewChainIfNeeded);
            Assert.Equal("raw", rule.Chain.Table);
        }

        [Fact]
        public void TestAppendRule()
        {
            IpTablesChainSet chains = new IpTablesChainSet(4);
            var rule = IpTablesRule.Parse("-A PREROUTING -s 1.1.1.1 -j TEST", null, chains, 4, "raw", IpTablesRule.ChainCreateMode.CreateNewChainIfNeeded);
            rule.AppendToRule("! -m devgroup --src-group 0x2");
        }

        [Fact]
        public void TestGetModuleOrLoad_CanLoadBareTargetAfterParse()
        {
            IpTablesChainSet chains = new IpTablesChainSet(4);
            var rule = IpTablesRule.Parse("-A INPUT -j MARK", null, chains, 4);

            var mark = rule.GetModuleOrLoad<MarkTargetModule>("MARK");

            Assert.NotNull(mark);
            mark.SetOrMark(1);
            Assert.Equal("-A INPUT -j MARK --set-xmark 0x1/0x1", rule.GetActionCommand());
        }

        [Fact]
        public void InitialCountersAreIncludedOnlyWhenRequested()
        {
            var chains = new IpTablesChainSet(4);
            var rule = IpTablesRule.Parse("-A INPUT -j ACCEPT", null, chains, 4);
            rule.Counters = new PacketCounters(bytes: 34, packets: 12);

            Assert.Equal("-A INPUT -j ACCEPT", rule.GetActionCommand());
            Assert.Equal("-A INPUT -c 12 34 -j ACCEPT",
                rule.GetActionCommand(incCounters: true));
        }

        [Fact]
        public void ShallowClonePreservesInitialCounters()
        {
            var chains = new IpTablesChainSet(4);
            var rule = IpTablesRule.Parse("-A INPUT -j ACCEPT", null, chains, 4);
            rule.Counters = new PacketCounters(bytes: 34, packets: 12);

            var clone = rule.ShallowClone();

            Assert.Equal(34, clone.Counters.Bytes);
            Assert.Equal(12, clone.Counters.Packets);
            Assert.Equal("-A INPUT -c 12 34 -j ACCEPT",
                clone.GetActionCommand(incCounters: true));
        }
    }
}
