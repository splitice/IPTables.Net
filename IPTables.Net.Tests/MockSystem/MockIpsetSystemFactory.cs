using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using SystemInteract;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Adapter;
using IPTables.Net.Iptables.IpSet;
using IPTables.Net.Netfilter.TableSync;
using NUnit.Framework;

namespace IPTables.Net.Tests.MockSystem
{
    class MockIpsetSystemFactory : ISystemFactory
    {
        public List<KeyValuePair<String, String>> Commands = new List<KeyValuePair<string, string>>();
        public ISystemProcess StartProcess(string command, string arguments)
        {
            Commands.Add(new KeyValuePair<string, string>(command, arguments));
            return new MockIptablesSystemProcess();
        }

        public void TestSync(IpSetSets rulesNew)
        {
            rulesNew.Sync((a)=>true, false);
        }

        public void TestSync(IpSetSets rulesNew, List<string> expectedCommands)
        {
            TestSync(rulesNew);

            CollectionAssert.AreEqual(expectedCommands, Commands.Select(a => a.Value).ToList());
        }
    }
}
