using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Adapter;
using IPTables.Net.Iptables.Adapter.Client;
using IPTables.Net.Iptables.NativeLibrary;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture(4)]
    [TestFixture(6)]
    class IptablesLibraryTest
    {
        private int _ipVersion;

        public static bool IsLinux
        {
            get
            {
                int p = (int)Environment.OSVersion.Platform;
                return (p == 4) || (p == 6) || (p == 128);
            }
        }

        public IptablesLibraryTest(int ipVersion)
        {
            _ipVersion = ipVersion;
        }

        private String GetBinary()
        {
            if (_ipVersion == 4)
            {
                return "iptables";
            }
            return "ip6tables";
        }

        [TestFixtureSetUp]
        public void TestStartup()
        {
            if (IsLinux)
            {
                Process.Start("/sbin/" + GetBinary(), "-N test2").WaitForExit();
                Process.Start("/sbin/" + GetBinary(), "-N test").WaitForExit();
                Process.Start("/sbin/" + GetBinary(), "-A test -j ACCEPT").WaitForExit();

                Process.Start("/sbin/" + GetBinary(), "-N test3").WaitForExit();
                Process.Start("/sbin/" + GetBinary(), "-A test3 -p tcp -m tcp --dport 80 -j ACCEPT").WaitForExit();
            }
        }

        [TestFixtureTearDown]
        public void TestDestroy()
        {
            if (IsLinux)
            {
                Process.Start("/sbin/"+GetBinary(), "-F test").WaitForExit();
                Process.Start("/sbin/"+GetBinary(), "-X test").WaitForExit();
                Process.Start("/sbin/"+GetBinary(), "-F test2").WaitForExit();
                Process.Start("/sbin/"+GetBinary(), "-X test2").WaitForExit();
                Process.Start("/sbin/"+GetBinary(), "-F test3").WaitForExit();
                Process.Start("/sbin/"+GetBinary(), "-X test3").WaitForExit();
            }
        }

        [Test]
        public void TestRuleOutput()
        {
            if (IsLinux)
            {
                Assert.AreEqual(0, IptcInterface.RefCount);
                var system = new IpTablesSystem(null, new IPTablesLibAdapter());
                using (var client = system.GetTableAdapter(_ipVersion))
                {
                    Debug.Assert(client is IPTablesLibAdapterClient);
                    var rules = client.ListRules("filter");
                    Debug.Assert(rules != null, "Expected to find filter table");
                    foreach (var chain in rules.Chains)
                    {
                        Assert.AreEqual(_ipVersion, chain.IpVersion, "Incorrect IP Version for chain: " + chain);
                    }
                    Assert.AreNotEqual(0, rules.Chains.SelectMany((a)=>a.Rules).Count());
                    foreach (var rule in rules.Chains.SelectMany((a) => a.Rules))
                    {
                        Assert.AreEqual(_ipVersion, rule.IpVersion, "Incorrect IP Version for rule: " + rule);
                    }
                }
                Assert.AreEqual(0, IptcInterface.RefCount);
            }   
        }


        [Test]
        public void TestRuleAdd()
        {
            if (IsLinux)
            {
                Assert.AreEqual(0, IptcInterface.RefCount);
                var system = new IpTablesSystem(null, new IPTablesLibAdapter());
                using (var client = system.GetTableAdapter(_ipVersion))
                {
                    Debug.Assert(client is IPTablesLibAdapterClient);
                    var rules = client.ListRules("filter");
                    var chain = new IpTablesChainSet(4);
                    foreach (var c in rules.Chains)
                    {
                        chain.AddChain(c as IpTablesChain);
                    }
                    var rule = IpTablesRule.Parse("-A test2 -p 80 -j ACCEPT", system, chain);
                    client.StartTransaction();
                    client.AddRule(rule);
                    client.EndTransactionCommit();


                    var proc = Process.Start("/sbin/" + GetBinary(), "-L test2");
                    proc.WaitForExit();
                    String listOutput = proc.StandardOutput.ReadToEnd();
                    Debug.Assert(listOutput.Contains("anywhere"), "must have created rule");
                }
                Assert.AreEqual(0, IptcInterface.RefCount);
            }
        }
    }
}
