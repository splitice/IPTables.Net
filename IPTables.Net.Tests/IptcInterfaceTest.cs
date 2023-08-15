using System;
using System.Threading;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Text;
using IPTables.Net.Iptables.NativeLibrary;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture(4)]
// FIXME: Fix bug in Ubuntu
//    [TestFixture(6)]
    class IptcInterfaceTest
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

        public IptcInterfaceTest(int ipVersion)
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

        [OneTimeSetUp]
        public void TestStartup()
        {
            if (IsLinux)
            {
                if (Environment.GetEnvironmentVariable("SKIP_SYSTEM_TESTS") == "1")
                {
                    Assert.Ignore();
                }
                Process.Start("/sbin/" + GetBinary(), "-F test").WaitForExit();

                Process.Start("/sbin/" + GetBinary(), "-N test2").WaitForExit();
                Process.Start("/sbin/" + GetBinary(), "-N test").WaitForExit();
                Process.Start("/sbin/" + GetBinary(), "-A test -j ACCEPT").WaitForExit();

                Process.Start("/sbin/" + GetBinary(), "-N test3").WaitForExit();
                Process.Start("/sbin/" + GetBinary(), "-A test3 -p tcp -m tcp --dport 80 -j ACCEPT").WaitForExit();
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
                Process.Start("/sbin/" + GetBinary(), "-D test -j ACCEPT").WaitForExit();
                Process.Start("/sbin/" + GetBinary(), "-F test").WaitForExit();
                Process.Start("/sbin/"+GetBinary(), "-X test").WaitForExit();
                Process.Start("/sbin/"+GetBinary(), "-F test2").WaitForExit();
                Process.Start("/sbin/"+GetBinary(), "-X test2").WaitForExit();
                Process.Start("/sbin/"+GetBinary(), "-F test3").WaitForExit();
                Process.Start("/sbin/"+GetBinary(), "-X test3").WaitForExit();
            }
        }

        [Test]
        public void TestRuleOutputSimple()
        {
            if (IsLinux)
            {
                Assert.AreEqual(0, IptcInterface.RefCount);
                using (IptcInterface iptc = new IptcInterface("filter", _ipVersion))
                {
                    var rules = iptc.GetRules("test");
                    Assert.AreEqual(1, rules.Count);
                    Assert.AreEqual("-A test -j ACCEPT", iptc.GetRuleString("test", rules[0]));
                }
                Assert.AreEqual(0, IptcInterface.RefCount);
            }   
        }

        [Test]
        public void TestRuleOutputModule()
        {
            if (IsLinux)
            {
                Assert.AreEqual(0, IptcInterface.RefCount);
                using (IptcInterface iptc = new IptcInterface("filter", _ipVersion))
                {
                    var rules = iptc.GetRules("test3");
                    Assert.AreEqual(1, rules.Count);
                    Assert.AreEqual("-A test3 -p tcp -m tcp --dport 80 -j ACCEPT", iptc.GetRuleString("test3", rules[0]));
                }
                Assert.AreEqual(0, IptcInterface.RefCount);
            }
        }

        [Test]
        public void TestRuleInput()
        {
            if (IsLinux)
            {
                Assert.AreEqual(0, IptcInterface.RefCount);
                using (IptcInterface iptc = new IptcInterface("filter", _ipVersion))
                {

                    var status = iptc.ExecuteCommand(_ipVersion == 4 ? "iptables -A test2 -d 1.1.1.1 -p tcp -m tcp --dport 80 -j ACCEPT" : "iptables -A test2 -d ::1 -p tcp -m tcp --dport 80 -j ACCEPT");
                    Assert.AreEqual(1, status, "Expected OK return value");

                    var rules = iptc.GetRules("test2");
                    Assert.AreEqual(1, rules.Count);
                    Assert.AreEqual(_ipVersion == 4 ? "-A test2 -d 1.1.1.1/32 -p tcp -m tcp --dport 80 -j ACCEPT" : "-A test2 -d ::1/128 -p tcp -m tcp --dport 80 -j ACCEPT",
                        iptc.GetRuleString("test2", rules[0]));
                }
                Assert.AreEqual(0, IptcInterface.RefCount);
            }
        }

        [Test]
        public void TestRuleIp()
        {
            if (IsLinux)
            {
                Assert.AreEqual(0, IptcInterface.RefCount);

                String ip;
                int cidr;
                if (_ipVersion == 4)
                {
                    ip = IPAddress.Loopback.ToString();
                    cidr = 32;
                }
                else
                {
                    ip = "::1";
                    cidr = 128;
                }
                var rule = "-A test3 -s " + ip + "/" + cidr + " -p tcp -m tcp --dport 80 -j ACCEPT";

                using (IptcInterface iptc = new IptcInterface("filter", _ipVersion))
                {
                    iptc.ExecuteCommand("ip6tables " + rule);
                    var rules = iptc.GetRules("test3");
                    Assert.AreEqual(2, rules.Count);
                    Assert.AreEqual(rule, iptc.GetRuleString("test3", rules[1]));
                }
                Assert.AreEqual(0, IptcInterface.RefCount);
            }
        }

        [Test]
        public void TestListChainsSimple()
        {
            if (IsLinux)
            {
                Assert.AreEqual(0, IptcInterface.RefCount);
                using (IptcInterface iptc = new IptcInterface("filter", _ipVersion))
                {

                    var chains = iptc.GetChains();
                    Assert.AreNotEqual(0, chains.Count, "Expected atleast one chain");
                }
                Assert.AreEqual(0, IptcInterface.RefCount);
            }
        }

        [Test]
        public void TestListChainsMangle()
        {
            if (IsLinux)
            {
                Assert.AreEqual(0, IptcInterface.RefCount);
                using (IptcInterface iptc = new IptcInterface("mangle", _ipVersion))
                {

                    var chains = iptc.GetChains();
                    Assert.AreNotEqual(0, chains.Count, "Expected atleast one chain");

                    List<String> expectedChains = new List<string>
                    {
                        "PREROUTING",
                        "INPUT",
                        "FORWARD",
                        "OUTPUT",
                        "POSTROUTING"
                    };
                    CollectionAssert.AreEqual(expectedChains, iptc.GetChains(), "first table chain test");

                    //Test repeatable
                    CollectionAssert.AreEqual(expectedChains, iptc.GetChains(), "second table chain test");
                }
                Assert.AreEqual(0, IptcInterface.RefCount);
            }
        }
    }
}
