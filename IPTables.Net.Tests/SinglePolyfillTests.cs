using System;
using IPTables.Net.Iptables;

namespace IPTables.Net.Tests
{
    public class SinglePolyfillTests
    {
        [Fact]
        public void TestPolyfillParse()
        {
            String rule = "-A INPUT -m unknown --unknown";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }


        [Fact]
        public void TestPolyfillParseMultiple()
        {
            String rule = "-A INPUT -m unknown --unknown -m unknown2";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }

        [Fact]
        public void TestPolyfillParseAdditionalOptionsAfter()
        {
            String rule = "-A INPUT -m unknown --unknown -p tcp -d 1.1.1.1 -m tcp --dport 80";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            IpTablesRule irule = IpTablesRule.Parse(rule, null, chains, 4);

            Assert.Equal(rule, irule.GetActionCommand());
        }

        [Fact]
        public void TestPolyfillArgumentsComparison1()
        {
            String rule = "-A INPUT -m unknown --unknown --unknown-2 1111 -p tcp -d 1.1.1.1 -m tcp --dport 80";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            Assert.True(IpTablesRule.Parse(rule, null, chains, 4).Compare(IpTablesRule.Parse(rule, null, chains, 4)));
        }

        [Fact]
        public void TestPolyfillArgumentsComparison2()
        {
            String rule =
                "-A INPUT -m unknown --unknown --unknown-2 1111 -m unknown2 --unknown2 -p tcp -d 1.1.1.1 -m tcp --dport 80";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            Assert.True(IpTablesRule.Parse(rule, null, chains, 4).Compare(IpTablesRule.Parse(rule, null, chains, 4)));
        }

        [Fact]
        public void TestPolyfillArgumentsComparison3()
        {
            String rule =
                "-A INPUT -m unknown --unknown --unknown-2 1111 -m unknown2 --unknown2 -p tcp -d 1.1.1.1 -m tcp --dport 80";
            String rule2 =
                "-A INPUT -m unknown2 --unknown2 -m unknown --unknown --unknown-2 1111 -p tcp -d 1.1.1.1 -m tcp --dport 80";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            Assert.True(IpTablesRule.Parse(rule, null, chains, 4).Compare(IpTablesRule.Parse(rule2, null, chains)));
        }

        [Fact]
        public void TestPolyfillArgumentsComparison4()
        {
            String rule =
                "-A INPUT -m unknown --unknown --unknown-2 \'this has spaces & a symbol\' -m unknown2 --unknown2 -p tcp -d 1.1.1.1 -m tcp --dport 80";
            String rule2 =
                "-A INPUT -m unknown2 --unknown2 -m unknown --unknown --unknown-2 \'this has spaces & a symbol\' -p tcp -d 1.1.1.1 -m tcp --dport 80";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            Assert.True(IpTablesRule.Parse(rule, null, chains, 4).Compare(IpTablesRule.Parse(rule2, null, chains)));
        }

        private void TestPolyfillArgumentsComparison5()
        {
            String rule = "-A INPUT -m unknown --unknown \'6&0xFF=0x6&&0>>22&0x33@12&0xFFFF=12333\' -g TEST";
            IpTablesChainSet chains = new IpTablesChainSet(4);

            Assert.Equal(IpTablesRule.Parse(rule, null, chains, 4), IpTablesRule.Parse(rule, null, chains, 4));
        }
    }
}
