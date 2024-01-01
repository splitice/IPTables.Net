using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using SystemInteract;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Adapter.Client;
using IPTables.Net.Iptables.TableSync;
using NUnit.Framework;

namespace IPTables.Net.TestFramework
{
    public class MockIptablesSystemFactory : ISystemFactory
    {
        public List<KeyValuePair<String, String>> ExecutionLog = new List<KeyValuePair<string, string>>();
        public Dictionary<KeyValuePair<String, String>,StreamReader[]> MockOutputs = new Dictionary<KeyValuePair<string, string>, StreamReader[]>();
        private readonly bool _strict;

        public MockIptablesSystemFactory(bool strict = false)
        {
            _strict = strict;
        }

        public ISystemProcess StartProcess(string command, string arguments)
        {
            var exe = new KeyValuePair<string, string>(command, arguments);
            ExecutionLog.Add(exe);
            StreamReader output = null, error = null;
            if (MockOutputs.TryGetValue(exe, out var mo))
            {
                if(mo.Length >= 1)
                {
                    output = mo[0];
                }
                if (MockOutputs[exe].Length >= 2)
                {
                    error = mo[1];
                }
            }
            else if(_strict)
            {
                throw new Exception("Mock output \"" + command + "\" " + arguments + " not found");
            }
            return new MockIptablesSystemProcess(output,error);
        }

        public Stream Open(string path, FileMode mode, FileAccess access)
        {
            throw new NotImplementedException();
        }

        public void TestSync<TSync>(IIPTablesAdapterClient client, IpTablesRuleSet rulesOriginal, IpTablesRuleSet rulesNew, TSync sync, List<string> expectedCommands = null) where TSync: IRuleSync
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
