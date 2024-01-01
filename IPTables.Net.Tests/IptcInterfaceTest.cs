using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using IPTables.Net.Iptables.NativeLibrary;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [NonParallelizable]
    [TestFixture(4)]
    //[TestFixture(6)]
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
            if(Path.Exists("/sbin/"+name)) return "/sbin/"+name;
            if(Path.Exists("/usr/sbin/"+name)) return "/usr/sbin/"+name;
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

                Console.WriteLine("Test Startup");

                var binary = GetBinary();
                Execute(binary, "-F test");

                Execute(binary, "-N test2");
                Process.Start(binary, "-N test").WaitForExit();
                Process.Start(binary, "-A test -j ACCEPT").WaitForExit();

                Process.Start(binary, "-N test3").WaitForExit();
                Process.Start(binary, "-A test3 -p tcp -m tcp --dport 80 -j ACCEPT").WaitForExit();
            }
        }

        private void Execute(string binary, string args)
        {
            var process = Process.Start(new ProcessStartInfo(binary, args){RedirectStandardError = true, RedirectStandardOutput = true});
            Console.WriteLine(process.StandardOutput.ReadToEnd());
            Console.Error.WriteLine(process.StandardError.ReadToEnd());
            process.WaitForExit();
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
                Console.WriteLine("Test Done");
                var binary = GetBinary();
                Process.Start(binary, "-D test -j ACCEPT").WaitForExit();
                Process.Start(binary, "-F test").WaitForExit();
                Process.Start(binary, "-X test").WaitForExit();
                Process.Start(binary, "-F test2").WaitForExit();
                //Process.Start(binary, "-X test2").WaitForExit();
                Process.Start(binary, "-F test3").WaitForExit();
                Process.Start(binary, " - X test3").WaitForExit();
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

                    var status = iptc.ExecuteCommand(_ipVersion == 4 ? "iptables -A test2 -d 1.1.1.1 -p tcp -m tcp --dport 80 -j ACCEPT" : "ip6tables -A test2 -d ::1 -p tcp -m tcp --dport 80 -j ACCEPT");
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
