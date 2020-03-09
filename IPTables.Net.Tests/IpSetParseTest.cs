using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
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
            Assert.AreEqual(IpSetType.Hash | IpSetType.Ip, set.Type);
            Assert.AreEqual(10, set.HashSize);
            Assert.AreEqual(14, set.MaxElem);

            Assert.AreEqual(toParse,set.GetCommand());
        }

        [Test]
        public void TestParseEntry1()
        {

            var set = IpSetSet.Parse("test_set hash:ip family inet hashsize 10 maxelem 14", null);

            IpSetSets sets = new IpSetSets(null);
            sets.AddSet(set);

            
            String toParse = "test_set 8.8.8.8";
            var entry = IpSetEntry.Parse(toParse, sets);

            Assert.AreEqual("test_set", entry.Set.Name);
            Assert.AreEqual(IPAddress.Parse("8.8.8.8"), entry.Cidr.Address);
        }

        [Test]
        public void TestParseEntry2()
        {

            var set = IpSetSet.Parse("test_set hash:ip,port family inet hashsize 10 maxelem 14", null);

            IpSetSets sets = new IpSetSets(null);
            sets.AddSet(set);


            String toParse = "test_set 8.8.8.8,tcp:80";
            var entry = IpSetEntry.Parse(toParse, sets);

            Assert.AreEqual("test_set", entry.Set.Name);
            Assert.AreEqual(IPAddress.Parse("8.8.8.8"), entry.Cidr.Address);
            Assert.AreEqual(80, entry.Port);
        }
    }
}
