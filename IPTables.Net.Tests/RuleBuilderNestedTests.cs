using System;
using System.Linq;
using System.Net;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.DataTypes;
using IPTables.Net.Iptables.Modules.Core;
using IPTables.Net.Iptables.Modules.Udp;
using IPTables.Net.Iptables.RuleGenerator;
using IPTables.Net.Tests.MockSystem;
using IPTables.Net.Tests.MockSystem.IpTablesRestore;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    internal class RuleBuilderNestedTests
    {
        [Test]
        public void TestNesting()
        {
            var mock = new MockIptablesSystemFactory();
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());
            IpTablesChainSet chains = new IpTablesChainSet();

            FeatureSplitter<MultiportAggregator<IPAddress>, String> ma = new FeatureSplitter<MultiportAggregator<IPAddress>, String>("INPUT", "filter", extractor, setter, nestedGenerator, "_");
            ma.AddRule(IpTablesRule.Parse("-A INPUT -s 8.1.1.1 -i eth0 -m udp --sport 1 -j ACCEPT", system, chains));
            ma.AddRule(IpTablesRule.Parse("-A INPUT -s 8.1.1.1 -i eth1 -m udp --sport 2 -j ACCEPT", system, chains));
            ma.AddRule(IpTablesRule.Parse("-A INPUT -s 8.1.1.2 -i eth0 -m udp --sport 3 -j ACCEPT", system, chains));

            IpTablesRuleSet rules = new IpTablesRuleSet(system);
            ma.Output(system, rules);

            Assert.AreEqual(3, rules.Chains.Count());
            Assert.AreEqual(2, rules.Chains.Skip(1).First().Rules.Count);
            Assert.AreEqual(1, rules.Chains.Skip(2).First().Rules.Count);
        }

        private MultiportAggregator<IPAddress> nestedGenerator(string arg1, string arg2)
        {
            return new MultiportAggregator<IPAddress>(arg1, arg2, extractSrcIp, extractSrcPort,
                MultiportAggregator<IPAddress>.SourcePortSetter, setSourceIp, "_");
        }

        private void setter(IpTablesRule arg1, String arg2)
        {
            arg1.GetModuleOrLoad<CoreModule>("core").InInterface = new ValueOrNot<String>(arg2);
        }

        private String extractor(IpTablesRule arg)
        {
            String addr = arg.GetModule<CoreModule>("core").InInterface.Value;
            arg.GetModule<CoreModule>("core").InInterface = new ValueOrNot<String>();
            return addr;
        }

        private void setSourceIp(IpTablesRule arg1, IPAddress arg2)
        {
            arg1.GetModuleOrLoad<CoreModule>("core").Source = new ValueOrNot<IpCidr>(new IpCidr(arg2, 32));
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