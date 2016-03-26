using System;
using System.Collections.Generic;
using System.IO;
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

            CollectionAssert.AreEqual(expected, systemFactory.ExecutionLog);
        }

        [Test]
        public void TestAddRule2()
        {
            var systemFactory = new MockIptablesSystemFactory();
            var ipUtils = new IpRuleController(systemFactory);
            ipUtils.Add("not", "from", "1.1.1.1", "lookup", "100");

            var expected = new List<KeyValuePair<String, String>>
            {
                new KeyValuePair<string, string> ("ip","rule add not from 1.1.1.1 lookup 100")
            };

            CollectionAssert.AreEqual(expected, systemFactory.ExecutionLog);
        }

        [Test]
        public void TestAddObjRule()
        {
            var systemFactory = new MockIptablesSystemFactory();
            var ipUtils = new IpRuleController(systemFactory);
            var obj = new IpObject();
            obj.Pairs.Add("from", "1.1.1.1");
            obj.Pairs.Add("lookup", "100");
            obj.Singles.Add("not");
            ipUtils.Add(obj);

            var expected = new List<KeyValuePair<String, String>>
            {
                new KeyValuePair<string, string> ("ip","rule add not from 1.1.1.1 lookup 100")
            };

            CollectionAssert.AreEqual(expected, systemFactory.ExecutionLog);
        }

        [Test]
        public void TestDeleteRule()
        {
            var systemFactory = new MockIptablesSystemFactory();
            var ipUtils = new IpRuleController(systemFactory);
            ipUtils.Delete("from", "1.1.1.1", "lookup", "100");

            var expected = new List<KeyValuePair<String, String>>
            {
                new KeyValuePair<string, string> ("ip","rule delete from 1.1.1.1 lookup 100")
            };

            CollectionAssert.AreEqual(expected, systemFactory.ExecutionLog);
        }

        [Test]
        public void TestGetRules()
        {
            var systemFactory = new MockIptablesSystemFactory();
            var output = "32766:  from all lookup main\n32767:  from all lookup default";
            systemFactory.MockOutputs.Add(new KeyValuePair<string, string>("ip"," rule show"), new StreamReader[]{new StreamReader(new MemoryStream(Encoding.ASCII.GetBytes(output)))});
            var ipUtils = new IpRuleController(systemFactory);
            var rules = ipUtils.GetAll();

            Assert.AreEqual(2, rules.Count);
            Assert.AreEqual("from all lookup main", ipUtils.ExportObject(rules[0]));
            Assert.AreEqual("from all lookup default", ipUtils.ExportObject(rules[1]));
        }
    }
}
