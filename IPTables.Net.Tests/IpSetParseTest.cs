using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using IPTables.Net.IpSet;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Tests
{
    public class IpSetParseTest
    {
        [Fact]
        public void TestParseSet1()
        {
            String toParse = "test_set hash:ip family inet hashsize 10 maxelem 14";

            var set = IpSetSet.Parse(toParse, null);

            Assert.Equal("test_set", set.Name);
            Assert.Equal(IpSetType.Hash | IpSetType.Ip, set.Type);
            Assert.Equal(10, set.HashSize);
            Assert.Equal((uint)14, set.MaxElem);

            Assert.Equal(toParse,set.GetCommand());
        }

        [Fact]
        public void TestParseSet2()
        {
            String toParse = "test_set hash:ip family inet hashsize 10 maxelem 14 timeout 613";

            var set = IpSetSet.Parse(toParse, null);

            Assert.Equal("test_set", set.Name);
            Assert.Equal(IpSetType.Hash | IpSetType.Ip, set.Type);
            Assert.Equal(10, set.HashSize);
            Assert.Equal((uint)14, set.MaxElem);
            Assert.Equal(613, set.Timeout);

            Assert.Equal(toParse, set.GetCommand());
        }

        [Fact]
        public void TestParseSet3()
        {
            String toParse = "test_set bitmap:port range 123-234 timeout 613";

            var set = IpSetSet.Parse(toParse, null);

            Assert.Equal("test_set", set.Name);
            Assert.Equal(IpSetType.Bitmap | IpSetType.Port, set.Type);
            Assert.Equal(new PortOrRange(123,234,'-'), set.BitmapRange);
            Assert.Equal(613, set.Timeout);

            Assert.Equal(toParse, set.GetCommand());
        }

        [Fact]
        public void TestParseEntry1()
        {

            var set = IpSetSet.Parse("test_set hash:ip family inet hashsize 10 maxelem 14", null);

            IpSetSets sets = new IpSetSets(null);
            sets.AddSet(set);

            
            String toParse = "test_set 8.8.8.8";
            var entry = IpSetEntry.Parse(toParse, sets);

            Assert.Equal("test_set", entry.Set.Name);
            Assert.Equal(IPAddress.Parse("8.8.8.8"), entry.Cidr.Address);
        }

        [Fact]
        public void TestParseEntry2()
        {

            var set = IpSetSet.Parse("test_set hash:ip,port family inet hashsize 10 maxelem 14", null);

            IpSetSets sets = new IpSetSets(null);
            sets.AddSet(set);


            String toParse = "test_set 8.8.8.8,tcp:80";
            var entry = IpSetEntry.Parse(toParse, sets);

            Assert.Equal("test_set", entry.Set.Name);
            Assert.Equal(IPAddress.Parse("8.8.8.8"), entry.Cidr.Address);
            Assert.Equal(80, entry.Port);
        }

        [Fact]
        public void TestParseEntryIp()
        {

            var set = IpSetSet.Parse("test_set hash:ip family inet hashsize 10 maxelem 14", null);

            IpSetSets sets = new IpSetSets(null);
            sets.AddSet(set);


            String toParse = "test_set 1.2.3.4";
            var entry = IpSetEntry.Parse(toParse, sets);

            Assert.Equal("test_set", entry.Set.Name);
            Assert.Equal(IPAddress.Parse("1.2.3.4"), entry.Cidr.Address);
        }


        [Fact]
        public void TestParseEntryIpPort()
        {

            var set = IpSetSet.Parse("test_set hash:ip,port family inet hashsize 10 maxelem 14", null);

            IpSetSets sets = new IpSetSets(null);
            sets.AddSet(set);


            String toParse = "test_set 1.1.1.1,tcp:80";
            var entry = IpSetEntry.Parse(toParse, sets);

            Assert.Equal("test_set", entry.Set.Name);
            Assert.Equal(IPAddress.Parse("1.1.1.1"), entry.Cidr.Address);
            Assert.Equal(80, entry.Port);
            Assert.Equal("tcp", entry.Protocol);
        }

        [Fact]
        public void TestParseEntryIpIpFlag()
        {

            var set = IpSetSet.Parse("test_set hash:ip,ip,flag family inet hashsize 10 maxelem 14", null);

            IpSetSets sets = new IpSetSets(null);
            sets.AddSet(set);


            String toParse = "test_set 1.1.1.1,2.2.2.2,80";
            var entry = IpSetEntry.Parse(toParse, sets);

            Assert.Equal("test_set", entry.Set.Name);
            Assert.Equal(IPAddress.Parse("1.1.1.1"), entry.Cidr.Address);
            Assert.Equal(80, entry.Port);;
        }

        [Fact]
        public void TestParseEntryCtIpPort()
        {

            var set = IpSetSet.Parse("test_set cthash:ip,port family inet hashsize 10 maxelem 14", null);

            IpSetSets sets = new IpSetSets(null);
            sets.AddSet(set);


            String toParse = "test_set 1.1.1.1,tcp:80";
            var entry = IpSetEntry.Parse(toParse, sets);

            Assert.Equal("test_set", entry.Set.Name);
            Assert.Equal(IPAddress.Parse("1.1.1.1"), entry.Cidr.Address);
            Assert.Equal(80, entry.Port);
            Assert.Equal("tcp", entry.Protocol);
        }


        [Fact]
        public void TestParseEntryIpIp()
        {

            var set = IpSetSet.Parse("test_set hash:ip,ip family inet hashsize 10 maxelem 14", null);

            IpSetSets sets = new IpSetSets(null);
            sets.AddSet(set);


            String toParse = "test_set 1.2.3.4,2.2.2.2";
            var entry = IpSetEntry.Parse(toParse, sets);

            Assert.Equal("test_set", entry.Set.Name);
            Assert.Equal(IPAddress.Parse("1.2.3.4"), entry.Cidr.Address);
            Assert.Equal(IPAddress.Parse("2.2.2.2"), entry.Cidr2.Address);
        }
        [Fact]
        public void TestParseEntryIpCounters()
        {

            var set = IpSetSet.Parse("test_set hash:ip family inet hashsize 10 maxelem 14", null);

            IpSetSets sets = new IpSetSets(null);
            sets.AddSet(set);


            String toParse = "test_set 1.2.3.4 packets 1 bytes 40";
            var entry = IpSetEntry.Parse(toParse, sets);

            Assert.Equal("test_set", entry.Set.Name);
            Assert.Equal(IPAddress.Parse("1.2.3.4"), entry.Cidr.Address);
        }
        [Fact]
        public void TestParseEntryIpIpCounters()
        {
            var set = IpSetSet.Parse("test_set hash:ip,ip family inet hashsize 10 maxelem 14", null);

            IpSetSets sets = new IpSetSets(null);
            sets.AddSet(set);


            String toParse = "test_set 1.2.3.4,2.2.2.2 packets 1 bytes 40";
            var entry = IpSetEntry.Parse(toParse, sets);

            Assert.Equal("test_set", entry.Set.Name);
            Assert.Equal(IPAddress.Parse("1.2.3.4"), entry.Cidr.Address);
            Assert.Equal(IPAddress.Parse("2.2.2.2"), entry.Cidr2.Address);
        }
    }
}
