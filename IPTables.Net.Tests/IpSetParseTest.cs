using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.IpSet;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    class IpSetParseTest
    {
        [Test]
        public void TestParseSet1()
        {
            String toParse = "test_set hash:ip family inet hashsize 10 maxelem 14";

            var set = IpSetSet.Parse(toParse, null);

            Assert.AreEqual("test_set", set.Name);
            Assert.AreEqual(IpSetType.HashIp, set.Type);
            Assert.AreEqual(10, set.HashSize);
            Assert.AreEqual(14, set.MaxElem);

            Assert.AreEqual(toParse,set.GetCommand());
        }
    }
}
