using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables;
using IPTables.Net.Tests.MockSystem;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    class IPTablesSync
    {
        [Test]
        public void TestAdd()
        {
            var mock = new MockIptablesSystemFactory();
            string chain;
            List<IpTablesRule> rulesOriginal = new List<IpTablesRule>()
                                               {
                                                   IpTablesRule.Parse("-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",mock, out chain),
                                                   IpTablesRule.Parse("-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2",mock, out chain)
                                               };
            List<IpTablesRule> rulesNew = new List<IpTablesRule>()
                                               {
                                                   IpTablesRule.Parse("-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",mock, out chain),
                                                   IpTablesRule.Parse("-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2",mock, out chain),
                                                   IpTablesRule.Parse("-A INPUT -d 1.2.3.4/16 -j DROP",mock, out chain)
                                               };

            List<String> expectedCommands = new List<String>() { rulesNew[2].GetFullCommand("INPUT","filter") };

            mock.TestSync(rulesOriginal, rulesNew, expectedCommands, mock);
        }

        [Test]
        public void TestAddDuplicate()
        {
            var mock = new MockIptablesSystemFactory();
            string chain;
            List<IpTablesRule> rulesOriginal = new List<IpTablesRule>()
                                               {
                                                   IpTablesRule.Parse("-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",mock, out chain),
                                                   IpTablesRule.Parse("-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2",mock, out chain)
                                               };
            List<IpTablesRule> rulesNew = new List<IpTablesRule>()
                                               {
                                                   IpTablesRule.Parse("-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",mock, out chain),
                                                   IpTablesRule.Parse("-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2",mock, out chain),
                                                   IpTablesRule.Parse("-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",mock, out chain)
                                               };

            List<String> expectedCommands = new List<String>() { rulesNew[2].GetFullCommand("INPUT", "filter") };

            mock.TestSync(rulesOriginal, rulesNew, expectedCommands, mock);
        }

        [Test]
        public void TestDelete()
        {
            var mock = new MockIptablesSystemFactory();
            string chain;
            List<IpTablesRule> rulesOriginal = new List<IpTablesRule>()
                                               {
                                                   IpTablesRule.Parse("-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",mock, out chain),
                                                   IpTablesRule.Parse("-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2",mock, out chain)
                                               };
            List<IpTablesRule> rulesNew = new List<IpTablesRule>()
                                               {
                                                   IpTablesRule.Parse("-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",mock, out chain),
                                               };

            List<String> expectedCommands = new List<String>() { rulesOriginal[1].GetFullCommand("INPUT", "filter", "-D") };

            mock.TestSync(rulesOriginal, rulesNew, expectedCommands, mock);
        }

        [Test]
        public void TestInsertMiddle()
        {
            var mock = new MockIptablesSystemFactory();
            string chain;
            List<IpTablesRule> rulesOriginal = new List<IpTablesRule>()
                                               {
                                                   IpTablesRule.Parse("-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",mock, out chain),
                                                   IpTablesRule.Parse("-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2",mock, out chain)
                                               };
            List<IpTablesRule> rulesNew = new List<IpTablesRule>()
                                               {
                                                   IpTablesRule.Parse("-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",mock, out chain),
                                                   IpTablesRule.Parse("-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 5",mock, out chain),
                                                   IpTablesRule.Parse("-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2",mock, out chain)
                                               };

            List<String> expectedCommands = new List<String>()
                                            {
                                                rulesOriginal[1].GetFullCommand("INPUT", "filter", "-D"),
                                                rulesNew[1].GetFullCommand("INPUT", "filter"),
                                                rulesNew[2].GetFullCommand("INPUT", "filter")
                                            };

            mock.TestSync(rulesOriginal, rulesNew, expectedCommands, mock);
        }

        /*[Test]
        public void TestUpdateEnd()
        {

        }

        [Test]
        public void TestUpdateBegin()
        {

        }

        [Test]
        public void TestUpdateMiddle()
        {

        }*/
    }
}
