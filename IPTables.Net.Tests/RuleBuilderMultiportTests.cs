using System;
using System.Linq;
using System.Net;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.DataTypes;
using IPTables.Net.Iptables.Helpers;
using IPTables.Net.Iptables.Modules.Core;
using IPTables.Net.Iptables.Modules.Udp;
using IPTables.Net.Iptables.RuleGenerator;
using IPTables.Net.Tests.MockSystem;
using IPTables.Net.Tests.MockSystem.IpTablesRestore;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class RuleBuilderMultiportTests
    {
        [Test]
        public void TestSingular()
        {
            var mock = new MockIptablesSystemFactory();
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());
            IpTablesChainSet chains = new IpTablesChainSet();

            MultiportAggregator<IPAddress> ma = new MultiportAggregator<IPAddress>("INPUT", "filter", extractSrcIp, extractSrcPort,
                PortRangeHelpers.SourcePortSetter, setSourceIp, "_", null);
            ma.AddRule(IpTablesRule.Parse("-A INPUT -s 8.1.1.1 -m udp --sport 1 -j ACCEPT", system, chains));
            ma.AddRule(IpTablesRule.Parse("-A INPUT -s 8.1.1.1 -m udp --sport 2 -j ACCEPT", system, chains));
            ma.AddRule(IpTablesRule.Parse("-A INPUT -s 8.1.1.2 -m udp --sport 3 -j ACCEPT", system, chains));

            IpTablesRuleSet rules = new IpTablesRuleSet(system);
            ma.Output(system, rules);

            Assert.AreEqual(1, rules.Chains.Count());
            Assert.AreEqual(2, rules.Chains.First().Rules.Count);
            Assert.AreEqual("-A INPUT -s 8.1.1.1 -j ACCEPT -m comment --comment '_|uXTlO5H/5x9hJe9WK1hw|1' -m multiport --sports 1:2", rules.Chains.First().Rules.First().GetActionCommand());
            Assert.AreEqual("-A INPUT -s 8.1.1.2 -j ACCEPT -m comment --comment '_|s5FXv5bN+84QgKZzjZ3Q|1' -m multiport --sports 3", rules.Chains.First().Rules.Skip(1).First().GetActionCommand());
        }

        [Test]
        public void TestMultiple()
        {
            var mock = new MockIptablesSystemFactory();
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());
            IpTablesChainSet chains = new IpTablesChainSet();

            MultiportAggregator<IPAddress> ma = new MultiportAggregator<IPAddress>("INPUT", "filter", extractSrcIp, extractSrcPort,
                PortRangeHelpers.SourcePortSetter, setSourceIp, "_");
            ma.AddRule(IpTablesRule.Parse("-A INPUT -s 8.1.1.1 -m udp --sport 10 -j ACCEPT", system, chains));
            ma.AddRule(IpTablesRule.Parse("-A INPUT -s 8.1.1.1 -m udp --sport 20 -j ACCEPT", system, chains));
            ma.AddRule(IpTablesRule.Parse("-A INPUT -s 8.1.1.1 -m udp --sport 30 -j ACCEPT", system, chains));
            ma.AddRule(IpTablesRule.Parse("-A INPUT -s 8.1.1.1 -m udp --sport 40 -j ACCEPT", system, chains));
            ma.AddRule(IpTablesRule.Parse("-A INPUT -s 8.1.1.1 -m udp --sport 50 -j ACCEPT", system, chains));
            ma.AddRule(IpTablesRule.Parse("-A INPUT -s 8.1.1.1 -m udp --sport 60 -j ACCEPT", system, chains));
            ma.AddRule(IpTablesRule.Parse("-A INPUT -s 8.1.1.1 -m udp --sport 70 -j ACCEPT", system, chains));
            ma.AddRule(IpTablesRule.Parse("-A INPUT -s 8.1.1.1 -m udp --sport 80 -j ACCEPT", system, chains));
            ma.AddRule(IpTablesRule.Parse("-A INPUT -s 8.1.1.1 -m udp --sport 90 -j ACCEPT", system, chains));
            ma.AddRule(IpTablesRule.Parse("-A INPUT -s 8.1.1.1 -m udp --sport 100 -j ACCEPT", system, chains));
            ma.AddRule(IpTablesRule.Parse("-A INPUT -s 8.1.1.1 -m udp --sport 110 -j ACCEPT", system, chains));
            ma.AddRule(IpTablesRule.Parse("-A INPUT -s 8.1.1.1 -m udp --sport 120 -j ACCEPT", system, chains));
            ma.AddRule(IpTablesRule.Parse("-A INPUT -s 8.1.1.1 -m udp --sport 130 -j ACCEPT", system, chains));
            ma.AddRule(IpTablesRule.Parse("-A INPUT -s 8.1.1.1 -m udp --sport 140 -j ACCEPT", system, chains));
            ma.AddRule(IpTablesRule.Parse("-A INPUT -s 8.1.1.1 -m udp --sport 150 -j ACCEPT", system, chains));
            ma.AddRule(IpTablesRule.Parse("-A INPUT -s 8.1.1.1 -m udp --sport 160 -j ACCEPT", system, chains));
            ma.AddRule(IpTablesRule.Parse("-A INPUT -s 8.1.1.1 -m udp --sport 170 -j ACCEPT", system, chains));
            ma.AddRule(IpTablesRule.Parse("-A INPUT -s 8.1.1.1 -m udp --sport 180 -j ACCEPT", system, chains));
            ma.AddRule(IpTablesRule.Parse("-A INPUT -s 8.1.1.1 -m udp --sport 190 -j ACCEPT", system, chains));

            IpTablesRuleSet rules = new IpTablesRuleSet(system);
            ma.Output(system, rules);

            Assert.AreEqual(2, rules.Chains.Count());
            Assert.AreEqual(1, rules.Chains.GetChainOrDefault("INPUT","filter").Rules.Count);
            Assert.AreEqual("-A INPUT -s 8.1.1.1 -j uXTlO5H/5x9hJe9WK1hw -m comment --comment '_|MA|INPUT_8.1.1.1'", 
                rules.Chains.GetChainOrDefault("INPUT", "filter").Rules.First().GetActionCommand());

            Assert.AreEqual("-A uXTlO5H/5x9hJe9WK1hw -j ACCEPT -m comment --comment '_|uXTlO5H/5x9hJe9WK1hw|1' -m multiport --sports 10,20,30,40,50,60,70,80,90,100,110,120,130,140,150",
                rules.Chains.GetChainOrDefault("uXTlO5H/5x9hJe9WK1hw", "filter").Rules.First().GetActionCommand());
        }

        private void setSourceIp(IpTablesRule arg1, IPAddress arg2)
        {
            arg1.GetModuleOrLoad<CoreModule>("core").Source = new ValueOrNot<IpCidr>(new IpCidr(arg2,32));
        }

        private PortOrRange extractSrcPort(IpTablesRule arg)
        {
            return arg.GetModule<UdpModule>("udp").SourcePort.Value;
        }

        private IPAddress extractSrcIp(IpTablesRule arg)
        {
            return arg.GetModule<CoreModule>("core").Source.Value.Address;
        }
    }
}