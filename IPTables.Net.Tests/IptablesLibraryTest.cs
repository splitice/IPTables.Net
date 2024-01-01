using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Adapter;
using IPTables.Net.Iptables.Adapter.Client;
using IPTables.Net.Iptables.NativeLibrary;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [NonParallelizable]
    [TestFixture(4)]
    //[TestFixture(6)]
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


        private String GetBinaryName()
        {
            if (_ipVersion == 4)
            {
                return "iptables";
            }
            return "ip6tables";
        }

        private String GetBinary()
        {
            var name = GetBinaryName();
            if (Path.Exists("/sbin/" + name)) return "/sbin/" + name;
            if (Path.Exists("/usr/sbin/" + name)) return "/usr/sbin/" + name;
            return name;
        }

        [OneTimeSetUp]
        public void TestStartup()
        {
            if (IsLinux)
            {
                if (Environment.GetEnvironmentVariable("SKIP_SYSTEM_TESTS") == "1")
                {
                    Assert.Ignore();
                }

                var binary = GetBinary();
                Process.Start(binary, "-N test2").WaitForExit();
                Process.Start(binary, "-N test").WaitForExit();
                Process.Start(binary, "-A test -j ACCEPT").WaitForExit();
                Process.Start(binary, "-N test3").WaitForExit();
                Process.Start(binary, "-A test3 -p tcp -m tcp --dport 80 -j ACCEPT").WaitForExit();
            }
        }

        [OneTimeTearDown]
        public void TestDestroy()
        {
            if (IsLinux)
            {
                if (Environment.GetEnvironmentVariable("SKIP_SYSTEM_TESTS") == "1")
                {
                    Assert.Ignore();
                }

                var binary = GetBinary();
                Process.Start(binary, "-F test").WaitForExit();
                Process.Start(binary, "-X test").WaitForExit();
                Process.Start(binary, "-F test2").WaitForExit();
                //Process.Start(binary, "-X test2").WaitForExit();
                Process.Start(binary, "-F test3").WaitForExit();
                Process.Start(binary, "-X test3").WaitForExit();
            }        }

        [Test]
        public void TestRuleOutput()
        {
            if (IsLinux)
            {
                Assert.AreEqual(0, IptcInterface.RefCount);
                var system = new IpTablesSystem(null, new IPTablesLibAdapter());
                using (var client = system.GetTableAdapter(_ipVersion))
                {
                    Assert.IsTrue(client is IPTablesLibAdapterClient);
                    var rules = client.ListRules("filter");
                    Assert.IsTrue(rules != null, "Expected to find filter table");
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
                    Assert.IsTrue(client is IPTablesLibAdapterClient);
                    var rules = client.ListRules("filter");
                    var chain = new IpTablesChainSet(_ipVersion);
                    foreach (var c in rules.Chains)
                    {
                        Assert.AreEqual(_ipVersion, c.IpVersion);
                        chain.AddChain(c as IpTablesChain);
                    }
                    var rule = IpTablesRule.Parse("-A test2 -p 80 -j ACCEPT", system, chain);
                    client.StartTransaction();
                    try
                    {
                        client.AddRule(rule);
                    }
                    finally
                    {
                        client.EndTransactionCommit();
                    }

                    var proc = Process.Start(new ProcessStartInfo(GetBinary(), "-L test2"){RedirectStandardOutput = true, UseShellExecute = false});
                    proc.WaitForExit();
                    String listOutput = proc.StandardOutput.ReadToEnd();
                    Assert.IsTrue(listOutput.Contains("anywhere"), "must have created rule");
                }
                Assert.AreEqual(0, IptcInterface.RefCount);
            }
        }
    }
}
