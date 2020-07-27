using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using IPTables.Net.Iptables.DataTypes;
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
        public void TestParseSet2()
        {
            String toParse = "test_set hash:ip family inet hashsize 10 maxelem 14 timeout 613";

            var set = IpSetSet.Parse(toParse, null);

            Assert.AreEqual("test_set", set.Name);
            Assert.AreEqual(IpSetType.Hash | IpSetType.Ip, set.Type);
            Assert.AreEqual(10, set.HashSize);
            Assert.AreEqual(14, set.MaxElem);
            Assert.AreEqual(613, set.Timeout);

            Assert.AreEqual(toParse, set.GetCommand());
        }

        [Test]
        public void TestParseSet3()
        {
            String toParse = "test_set bitmap:port range 123-234 timeout 613";

            var set = IpSetSet.Parse(toParse, null);

            Assert.AreEqual("test_set", set.Name);
            Assert.AreEqual(IpSetType.Bitmap | IpSetType.Port, set.Type);
            Assert.AreEqual(new PortOrRange(123,234,'-'), set.BitmapRange);
            Assert.AreEqual(613, set.Timeout);

            Assert.AreEqual(toParse, set.GetCommand());
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

        [Test]
        public void TestParseEntryIp()
        {

            var set = IpSetSet.Parse("test_set hash:ip family inet hashsize 10 maxelem 14", null);

            IpSetSets sets = new IpSetSets(null);
            sets.AddSet(set);


            String toParse = "test_set 1.2.3.4";
            var entry = IpSetEntry.Parse(toParse, sets);

            Assert.AreEqual("test_set", entry.Set.Name);
            Assert.AreEqual(IPAddress.Parse("1.2.3.4"), entry.Cidr.Address);
        }


        [Test]
        public void TestParseEntryIpPort()
        {

            var set = IpSetSet.Parse("test_set hash:ip,port family inet hashsize 10 maxelem 14", null);

            IpSetSets sets = new IpSetSets(null);
            sets.AddSet(set);


            String toParse = "test_set 1.1.1.1,tcp:80";
            var entry = IpSetEntry.Parse(toParse, sets);

            Assert.AreEqual("test_set", entry.Set.Name);
            Assert.AreEqual(IPAddress.Parse("1.1.1.1"), entry.Cidr.Address);
            Assert.AreEqual(80, entry.Port);
            Assert.AreEqual("tcp", entry.Protocol);
        }


        [Test]
        public void TestParseEntryIpIp()
        {

            var set = IpSetSet.Parse("test_set hash:ip,ip family inet hashsize 10 maxelem 14", null);

            IpSetSets sets = new IpSetSets(null);
            sets.AddSet(set);


            String toParse = "test_set 1.2.3.4,2.2.2.2";
            var entry = IpSetEntry.Parse(toParse, sets);

            Assert.AreEqual("test_set", entry.Set.Name);
            Assert.AreEqual(IPAddress.Parse("1.2.3.4"), entry.Cidr.Address);
            Assert.AreEqual(IPAddress.Parse("2.2.2.2"), entry.Cidr2.Address);
        }
        [Test]
        public void TestParseEntryIpCounters()
        {

            var set = IpSetSet.Parse("test_set hash:ip family inet hashsize 10 maxelem 14", null);

            IpSetSets sets = new IpSetSets(null);
            sets.AddSet(set);


            String toParse = "test_set 1.2.3.4 packets 1 bytes 40";
            var entry = IpSetEntry.Parse(toParse, sets);

            Assert.AreEqual("test_set", entry.Set.Name);
            Assert.AreEqual(IPAddress.Parse("1.2.3.4"), entry.Cidr.Address);
        }
        [Test]
        public void TestParseEntryIpIpCounters()
        {
            var set = IpSetSet.Parse("test_set hash:ip,ip family inet hashsize 10 maxelem 14", null);

            IpSetSets sets = new IpSetSets(null);
            sets.AddSet(set);


            String toParse = "test_set 1.2.3.4,2.2.2.2 packets 1 bytes 40";
            var entry = IpSetEntry.Parse(toParse, sets);

            Assert.AreEqual("test_set", entry.Set.Name);
            Assert.AreEqual(IPAddress.Parse("1.2.3.4"), entry.Cidr.Address);
            Assert.AreEqual(IPAddress.Parse("2.2.2.2"), entry.Cidr2.Address);
        }
    }
}
