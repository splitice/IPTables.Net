using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using IPTables.Net.IpUtils;
using IPTables.Net.IpUtils.Utils;
using IPTables.Net.TestFramework;
using Microsoft.VisualStudio.TestPlatform.Utilities;

namespace IPTables.Net.Tests
{
    public class IpUtilsRuleTests
    {
        [Fact]
        public void TestParseRule()
        {
            var systemFactory = new MockIptablesSystemFactory(true);
            var ipUtils = new IpRuleController(systemFactory);
            var one = ipUtils.ParseObjectInternal("default via 10.17.199.1 dev s4  table 200", "to");
            var two = ipUtils.ParseObjectInternal("default via 10.17.199.1 dev s4 table 200", "to");

            Assert.Equal(one.Pairs, two.Pairs);
            Assert.Equal("default", one.Pairs["to"]);
            Assert.Equal("200",one.Pairs["table"]);
        }

        [Fact]
        public void TestParsePref()
        {
            var systemFactory = new MockIptablesSystemFactory(true);
            var ipUtils = new IpRuleController(systemFactory);
            var one = ipUtils.ParseObject("0: from all fwmark 0x1000200/0x1ffff00 lookup 15002");
        }

        [Fact]
        public void TestAddRule()
        {
            var systemFactory = new MockIptablesSystemFactory(true);
            systemFactory.MockOutputs.Add(new KeyValuePair<string, string>("ip", "rule add from 1.1.1.1 lookup 100"), new StreamReader[] { new StreamReader(new MemoryStream(Encoding.ASCII.GetBytes(""))) });
            var ipUtils = new IpRuleController(systemFactory);
            ipUtils.Add("from","1.1.1.1","lookup","100");

            var expected = new List<KeyValuePair<String, String>>
            {
                new KeyValuePair<string, string> ("ip","rule add from 1.1.1.1 lookup 100")
            };

            Assert.Equal(expected, systemFactory.ExecutionLog);
        }

        [Fact]
        public void TestAddRule2()
        {
            var systemFactory = new MockIptablesSystemFactory(true);
            systemFactory.MockOutputs.Add(new KeyValuePair<string, string>("ip", "rule add not from 1.1.1.1 lookup 100"), new StreamReader[] { new StreamReader(new MemoryStream(Encoding.ASCII.GetBytes(""))) });
            var ipUtils = new IpRuleController(systemFactory);
            ipUtils.Add("not", "from", "1.1.1.1", "lookup", "100");

            var expected = new List<KeyValuePair<String, String>>
            {
                new KeyValuePair<string, string> ("ip","rule add not from 1.1.1.1 lookup 100")
            };

            Assert.Equal(expected, systemFactory.ExecutionLog);
        }

        [Fact]
        public void TestAddObjRule()
        {
            var systemFactory = new MockIptablesSystemFactory(true);


            systemFactory.MockOutputs.Add(new KeyValuePair<string, string>("ip", "rule add not from 1.1.1.1 lookup 100"), new StreamReader[] { new StreamReader(new MemoryStream(Encoding.ASCII.GetBytes(""))) });

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

            Assert.Equal(expected, systemFactory.ExecutionLog);
        }

        [Fact]
        public void TestDeleteRule()
        {
            var systemFactory = new MockIptablesSystemFactory(true);
            systemFactory.MockOutputs.Add(new KeyValuePair<string, string>("ip", "rule delete from 1.1.1.1 lookup 100"), new StreamReader[] { new StreamReader(new MemoryStream(Encoding.ASCII.GetBytes(""))) });
            var ipUtils = new IpRuleController(systemFactory);
            ipUtils.Delete("from", "1.1.1.1", "lookup", "100");

            var expected = new List<KeyValuePair<String, String>>
            {
                new KeyValuePair<string, string> ("ip","rule delete from 1.1.1.1 lookup 100")
            };

            Assert.Equal(expected, systemFactory.ExecutionLog);
        }

        [Fact]
        public void TestDeleteRuleId()
        {
            var systemFactory = new MockIptablesSystemFactory(true);
            systemFactory.MockOutputs.Add(new KeyValuePair<string, string>("ip", "rule delete pref 100 from 1.1.1.1"), new StreamReader[] { new StreamReader(new MemoryStream(Encoding.ASCII.GetBytes(""))) });
            var ipUtils = new IpRuleController(systemFactory);
            IpObject ipObject = new IpObject();
            ipObject.Pairs.Add("pref","100");
            ipObject.Pairs.Add("from","1.1.1.1");
            ipUtils.Delete(ipObject);

            var expected = new List<KeyValuePair<String, String>>
            {
                new KeyValuePair<string, string> ("ip","rule delete pref 100 from 1.1.1.1")
            };

            Assert.Equal(expected, systemFactory.ExecutionLog);
        }

        [Fact]
        public void TestGetRules()
        {
            var systemFactory = new MockIptablesSystemFactory(true);
            var output = "32766:   from all lookup main\n32767:  from all lookup default";
            systemFactory.MockOutputs.Add(new KeyValuePair<string, string>("ip","rule show"), new StreamReader[]{new StreamReader(new MemoryStream(Encoding.ASCII.GetBytes(output)))});
            var ipUtils = new IpRuleController(systemFactory);
            var rules = ipUtils.GetAll();

            Assert.Equal(2, rules.Count);
            Assert.Equal("pref 32766 from all lookup main", string.Join(" ", ipUtils.ExportObject(rules[0])));
            Assert.Equal("pref 32767 from all lookup default", string.Join(" ", ipUtils.ExportObject(rules[1])));
        }
    }
}
