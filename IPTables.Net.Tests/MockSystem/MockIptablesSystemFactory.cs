using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SystemInteract;
using IPTables.Net.Iptables;
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

        public void TestSync(List<IpTablesRule> rulesOriginal, List<IpTablesRule> rulesNew, List<string> expectedCommands, MockIptablesSystemFactory mock)
        {
            IpTablesSystem sys = new IpTablesSystem(mock);
            IpTablesChain chain = new IpTablesChain("filter", "INPUT", sys, rulesOriginal);
            chain.Sync(rulesNew);

            CollectionAssert.AreEqual(expectedCommands, Commands.Select(a => a.Value));
        }
    }
}
