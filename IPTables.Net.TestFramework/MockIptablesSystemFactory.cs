using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using SystemInteract;
using IPTables.Net.Iptables;
using IPTables.Net.Netfilter;
using IPTables.Net.Netfilter.TableSync;
using NUnit.Framework;

namespace IPTables.Net.TestFramework
{
    public class MockIptablesSystemFactory : ISystemFactory
    {
        public List<KeyValuePair<String, String>> ExecutionLog = new List<KeyValuePair<string, string>>();
        public Dictionary<KeyValuePair<String, String>,StreamReader[]> MockOutputs = new Dictionary<KeyValuePair<string, string>, StreamReader[]>();

        public ISystemProcess StartProcess(string command, string arguments)
        {
            var exe = new KeyValuePair<string, string>(command, arguments);
            ExecutionLog.Add(exe);
            StreamReader output = null, error = null;
            if (MockOutputs.ContainsKey(exe))
            {
                if(MockOutputs[exe].Length >= 1)
                {
                    output = MockOutputs[exe][0];
                }
                if (MockOutputs[exe].Length >= 2)
                {
                    error = MockOutputs[exe][1];
                }
            }
            return new MockIptablesSystemProcess(output,error);
        }

        public Stream Open(string path, FileMode mode, FileAccess access)
        {
            throw new NotImplementedException();
        }

        public void TestSync<TSync>(INetfilterAdapterClient client, IpTablesRuleSet rulesOriginal, IpTablesRuleSet rulesNew, TSync sync, List<string> expectedCommands = null) where TSync: INetfilterSync<IpTablesRule>
        {
            IpTablesChain chain = rulesOriginal.Chains.First();

            chain.Sync(client, rulesNew.Chains.First().Rules, sync);

            if (expectedCommands != null)
            {
                CollectionAssert.AreEqual(expectedCommands, ExecutionLog.Select(a => a.Value).ToList());
            }
        }
    }
}
