using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using SystemInteract;
using IPTables.Net.Iptables;
using IPTables.Net.Netfilter.TableSync;
using NUnit.Framework;

namespace IPTables.Net.TestFramework
{
    public class MockIptablesSystemFactory : ISystemFactory
    {
        public List<KeyValuePair<String, String>> Commands = new List<KeyValuePair<string, string>>();
        public ISystemProcess StartProcess(string command, string arguments)
        {
            Commands.Add(new KeyValuePair<string, string>(command, arguments));
            return new MockIptablesSystemProcess();
        }

        public Stream Open(string path, FileMode mode, FileAccess access)
        {
            throw new NotImplementedException();
        }

        public void TestSync(IpTablesRuleSet rulesOriginal, IpTablesRuleSet rulesNew, Func<IpTablesRule, IpTablesRule, bool> commentComparer = null)
        {
            IpTablesChain chain = rulesOriginal.Chains.First();

            DefaultNetfilterSync<IpTablesRule> sync = new DefaultNetfilterSync<IpTablesRule>(commentComparer,null);

            if (commentComparer == null)
                chain.Sync(rulesNew.Chains.First().Rules, sync);
            else
                chain.Sync(rulesNew.Chains.First().Rules, sync);
        }

        public void TestSync(IpTablesRuleSet rulesOriginal, IpTablesRuleSet rulesNew, List<string> expectedCommands, Func<IpTablesRule, IpTablesRule, bool> commentComparer = null)
        {
            TestSync(rulesOriginal, rulesNew, commentComparer);

            CollectionAssert.AreEqual(expectedCommands, Commands.Select(a => a.Value).ToList());
        }
    }
}
