using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SystemInteract;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Adapter;
using NUnit.Framework;

namespace IPTables.Net.Tests.MockSystem
{
    class MockIptablesSystemFactory: ISystemFactory
    {
        public List<KeyValuePair<String, String>> Commands = new List<KeyValuePair<string, string>>();
        public ISystemProcess StartProcess(string command, string arguments)
        {
            Commands.Add(new KeyValuePair<string, string>(command, arguments));
            return new MockIptablesSystemProcess();
        }

        public void TestSync(IpTablesRuleSet rulesOriginal, IpTablesRuleSet rulesNew, MockIptablesSystemFactory mock, Func<IpTablesRule, IpTablesRule, bool> commentComparer = null)
        {
            IpTablesChain chain = rulesOriginal.Chains.First();

            if (commentComparer == null)
                chain.Sync(rulesNew.Chains.First().Rules);
            else
                chain.Sync(rulesNew.Chains.First().Rules, commentComparer);
        }

        public void TestSync(IpTablesRuleSet rulesOriginal, IpTablesRuleSet rulesNew, List<string> expectedCommands, MockIptablesSystemFactory mock, Func<IpTablesRule, IpTablesRule, bool> commentComparer = null)
        {
            TestSync(rulesOriginal, rulesNew, mock, commentComparer);

            CollectionAssert.AreEqual(expectedCommands, Commands.Select(a => a.Value).ToList());
        }
    }
}
