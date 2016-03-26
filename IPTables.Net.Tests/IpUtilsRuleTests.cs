using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using IPTables.Net.Iptables.IpSet;
using IPTables.Net.Iptables.IpSet.Adapter;
using IPTables.Net.IpUtils;
using IPTables.Net.TestFramework;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    class IpUtilsRuleTests
    {
        [Test]
        public void TestAddRule()
        {
            var systemFactory = new MockIptablesSystemFactory();
            var ipUtils = new IpRuleController(systemFactory);
            ipUtils.Add("from","1.1.1.1","lookup","100");

            var expected = new List<KeyValuePair<String, String>>
            {
                new KeyValuePair<string, string> ("ip","rule add from 1.1.1.1 lookup 100")
            };

            CollectionAssert.AreEqual(expected, systemFactory.Commands);
        }

    }
}
