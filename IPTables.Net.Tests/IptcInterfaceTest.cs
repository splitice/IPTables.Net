using System;
using System.Collections.Generic;
using System.Net;
using IPTables.Net.Iptables.NativeLibrary;

namespace IPTables.Net.Tests
{
    public sealed class IptcInterfaceFixture : IDisposable
    {
        public int IpVersion => IptablesSystemTestSupport.IpVersion;

        public string SkipReason { get; }

        public IptcInterfaceFixture()
        {
            SkipReason = TestEnvironment.GetLinuxSystemTestSkipReason();
            if (SkipReason != null)
            {
                return;
            }

            Console.WriteLine("Test Startup");

            var binary = GetBinary();
            IptablesSystemTestSupport.CleanupTestChains(binary);
            IptablesSystemTestSupport.RequireSuccess(binary, "-N test2");
            IptablesSystemTestSupport.RequireSuccess(binary, "-N test");
            IptablesSystemTestSupport.RequireSuccess(binary, "-A test -j ACCEPT");
            IptablesSystemTestSupport.RequireSuccess(binary, "-N test3");
            IptablesSystemTestSupport.RequireSuccess(binary, "-A test3 -p tcp -m tcp --dport 80 -j ACCEPT");
        }

        public string GetBinary()
        {
            return IptablesSystemTestSupport.GetBinary(IpVersion);
        }

        public void SkipIfNeeded()
        {
            if (SkipReason != null)
            {
                Assert.Skip(SkipReason);
            }
        }

        public void Dispose()
        {
            if (SkipReason != null)
            {
                return;
            }

            Console.WriteLine("Test Done");
            IptablesSystemTestSupport.CleanupTestChains(GetBinary());
        }
    }

    [Collection(SystemIptablesCollectionDefinition.Name)]
    public class IptcInterfaceTest : IClassFixture<IptcInterfaceFixture>
    {
        private readonly IptcInterfaceFixture _fixture;

        public IptcInterfaceTest(IptcInterfaceFixture fixture)
        {
            _fixture = fixture;
        }

        [Fact]
        public void TestRuleOutputSimple()
        {
            _fixture.SkipIfNeeded();

            Assert.Equal(0, IptcInterface.RefCount);
            using (var iptc = new IptcInterface("filter", _fixture.IpVersion))
            {
                var rules = iptc.GetRules("test");
                Assert.Equal(1, rules.Count);
                Assert.Equal("-A test -j ACCEPT", iptc.GetRuleString("test", rules[0]));
            }
            Assert.Equal(0, IptcInterface.RefCount);
        }

        [Fact]
        public void TestRuleOutputModule()
        {
            _fixture.SkipIfNeeded();

            Assert.Equal(0, IptcInterface.RefCount);
            using (var iptc = new IptcInterface("filter", _fixture.IpVersion))
            {
                var rules = iptc.GetRules("test3");
                Assert.Equal(1, rules.Count);
                Assert.Equal("-A test3 -p tcp -m tcp --dport 80 -j ACCEPT", iptc.GetRuleString("test3", rules[0]));
            }
            Assert.Equal(0, IptcInterface.RefCount);
        }

        [Fact]
        public void TestRuleInput()
        {
            _fixture.SkipIfNeeded();

            Assert.Equal(0, IptcInterface.RefCount);
            using (var iptc = new IptcInterface("filter", _fixture.IpVersion))
            {
                var status = iptc.ExecuteCommand(_fixture.IpVersion == 4
                    ? "iptables -A test2 -d 1.1.1.1 -p tcp -m tcp --dport 80 -j ACCEPT"
                    : "ip6tables -A test2 -d ::1 -p tcp -m tcp --dport 80 -j ACCEPT");
                Assert.True(status == 1, "Expected OK return value");

                var rules = iptc.GetRules("test2");
                Assert.Equal(1, rules.Count);
                Assert.Equal(
                    _fixture.IpVersion == 4
                        ? "-A test2 -d 1.1.1.1/32 -p tcp -m tcp --dport 80 -j ACCEPT"
                        : "-A test2 -d ::1/128 -p tcp -m tcp --dport 80 -j ACCEPT",
                    iptc.GetRuleString("test2", rules[0]));
            }
            Assert.Equal(0, IptcInterface.RefCount);
        }

        [Fact]
        public void TestRuleIp()
        {
            _fixture.SkipIfNeeded();

            Assert.Equal(0, IptcInterface.RefCount);

            string ip;
            int cidr;
            if (_fixture.IpVersion == 4)
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

            using (var iptc = new IptcInterface("filter", _fixture.IpVersion))
            {
                iptc.ExecuteCommand("ip6tables " + rule);
                var rules = iptc.GetRules("test3");
                Assert.Equal(2, rules.Count);
                Assert.Equal(rule, iptc.GetRuleString("test3", rules[1]));
            }
            Assert.Equal(0, IptcInterface.RefCount);
        }

        [Fact]
        public void TestListChainsSimple()
        {
            _fixture.SkipIfNeeded();

            Assert.Equal(0, IptcInterface.RefCount);
            using (var iptc = new IptcInterface("filter", _fixture.IpVersion))
            {
                var chains = iptc.GetChains();
                Assert.True(chains.Count != 0, "Expected atleast one chain");
            }
            Assert.Equal(0, IptcInterface.RefCount);
        }

        [Fact]
        public void TestListChainsMangle()
        {
            _fixture.SkipIfNeeded();

            Assert.Equal(0, IptcInterface.RefCount);
            using (var iptc = new IptcInterface("mangle", _fixture.IpVersion))
            {
                var chains = iptc.GetChains();
                Assert.True(chains.Count != 0, "Expected atleast one chain");

                List<string> expectedChains = new List<string>
                {
                    "PREROUTING",
                    "INPUT",
                    "FORWARD",
                    "OUTPUT",
                    "POSTROUTING"
                };

                Assert.Equal(expectedChains, iptc.GetChains());
                Assert.Equal(expectedChains, iptc.GetChains());
            }
            Assert.Equal(0, IptcInterface.RefCount);
        }
    }
}
