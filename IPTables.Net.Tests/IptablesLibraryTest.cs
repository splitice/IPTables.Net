using System;
using System.Diagnostics;
using System.Linq;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Adapter;
using IPTables.Net.Iptables.Adapter.Client;
using IPTables.Net.Iptables.NativeLibrary;

namespace IPTables.Net.Tests
{
    public sealed class IptablesLibraryFixture : IDisposable
    {
        public int IpVersion => IptablesSystemTestSupport.IpVersion;

        public string SkipReason { get; }

        public IptablesLibraryFixture()
        {
            SkipReason = TestEnvironment.GetLinuxSystemTestSkipReason();
            if (SkipReason != null)
            {
                return;
            }

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

            IptablesSystemTestSupport.CleanupTestChains(GetBinary());
        }
    }

    [Collection(SystemIptablesCollectionDefinition.Name)]
    public class IptablesLibraryTest : IClassFixture<IptablesLibraryFixture>
    {
        private readonly IptablesLibraryFixture _fixture;

        public IptablesLibraryTest(IptablesLibraryFixture fixture)
        {
            _fixture = fixture;
        }

        [Fact]
        public void TestRuleOutput()
        {
            _fixture.SkipIfNeeded();

            Assert.Equal(0, IptcInterface.RefCount);
            var system = new IpTablesSystem(null, new IPTablesLibAdapter());
            using (var client = system.GetTableAdapter(_fixture.IpVersion))
            {
                Assert.True(client is IPTablesLibAdapterClient);
                var rules = client.ListRules("filter");
                Assert.NotNull(rules);

                foreach (var chain in rules.Chains)
                {
                    Assert.True(chain.IpVersion == _fixture.IpVersion, "Incorrect IP Version for chain: " + chain);
                }

                Assert.True(rules.Chains.SelectMany(a => a.Rules).Any(), "Expected at least one rule");

                foreach (var rule in rules.Chains.SelectMany(a => a.Rules))
                {
                    Assert.True(rule.IpVersion == _fixture.IpVersion, "Incorrect IP Version for rule: " + rule);
                }
            }
            Assert.Equal(0, IptcInterface.RefCount);
        }

        [Fact]
        public void TestRuleAdd()
        {
            _fixture.SkipIfNeeded();

            Assert.Equal(0, IptcInterface.RefCount);
            var system = new IpTablesSystem(null, new IPTablesLibAdapter());
            using (var client = system.GetTableAdapter(_fixture.IpVersion))
            {
                Assert.True(client is IPTablesLibAdapterClient);
                var rules = client.ListRules("filter");
                Assert.NotNull(rules);

                var chain = new IpTablesChainSet(_fixture.IpVersion);
                foreach (var existingChain in rules.Chains)
                {
                    Assert.Equal(_fixture.IpVersion, existingChain.IpVersion);
                    chain.AddChain(existingChain as IpTablesChain);
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

                using (var process = Process.Start(new ProcessStartInfo(_fixture.GetBinary(), "-L test2")
                {
                    RedirectStandardOutput = true,
                    UseShellExecute = false
                }))
                {
                    process.WaitForExit();
                    string listOutput = process.StandardOutput.ReadToEnd();
                    Assert.True(listOutput.Contains("anywhere"), "must have created rule");
                }
            }
            Assert.Equal(0, IptcInterface.RefCount);
        }
    }
}
