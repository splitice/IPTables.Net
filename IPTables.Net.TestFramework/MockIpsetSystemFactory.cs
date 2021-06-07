using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using SystemInteract;
using IPTables.Net.IpSet;
using NUnit.Framework;

namespace IPTables.Net.TestFramework
{
    public class MockIpsetSystemFactory : ISystemFactory
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
