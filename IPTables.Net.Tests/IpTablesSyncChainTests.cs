using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Modules;
using IPTables.Net.Iptables.Modules.Comment;
using IPTables.Net.Tests.MockSystem;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    class IpTablesSyncChainTests
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

            List<String> expectedCommands = new List<String>() { rulesOriginal[1].GetFullCommand("INPUT", "-D") };

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
                                                rulesOriginal[1].GetFullCommand("INPUT", "-D"),
                                                rulesNew[1].GetFullCommand("INPUT", "filter"),
                                                rulesNew[2].GetFullCommand("INPUT", "filter")
                                            };

            mock.TestSync(rulesOriginal, rulesNew, expectedCommands, mock);
        }

        /// <summary>
        /// Comparison that detirmines equality based on comment text
        /// </summary>
        /// <param name="rule1"></param>
        /// <param name="rule2"></param>
        /// <returns></returns>
        static bool CommentComparer(IpTablesRule rule1, IpTablesRule rule2)
        {
            var comment1 = rule1.GetModule<CommentModule>("comment");
            var comment2 = rule2.GetModule<CommentModule>("comment");

            if (comment1 == null || comment2 == null)
                return false;

            return comment1.CommentText == comment2.CommentText;
        }

        [Test]
        public void TestUpdateEnd()
        {
            var mock = new MockIptablesSystemFactory();
            string chain;
            List<IpTablesRule> rulesOriginal = new List<IpTablesRule>()
                                               {
                                                   IpTablesRule.Parse("-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10 -m comment --comment \"ID1\"",mock, out chain,1),
                                                   IpTablesRule.Parse("-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2 -m comment --comment \"ID2\"",mock, out chain,2)
                                               };
            List<IpTablesRule> rulesNew = new List<IpTablesRule>()
                                               {
                                                   IpTablesRule.Parse("-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10 -m comment --comment \"ID1\"",mock, out chain,1),
                                                   IpTablesRule.Parse("-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 5 -m comment --comment \"ID2\"",mock, out chain,2),
                                               };

            List<String> expectedCommands = new List<String>()
                                            {
                                                rulesNew[1].GetFullCommand("INPUT", "-R")
                                            };

            mock.TestSync(rulesOriginal, rulesNew, expectedCommands, mock, CommentComparer);
        }

        [Test]
        public void TestUpdateBegin()
        {
            var mock = new MockIptablesSystemFactory();
            string chain;
            List<IpTablesRule> rulesOriginal = new List<IpTablesRule>()
                                               {
                                                   IpTablesRule.Parse("-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10 -m comment --comment \"ID1\"",mock, out chain,1),
                                                   IpTablesRule.Parse("-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2 -m comment --comment \"ID2\"",mock, out chain,2)
                                               };
            List<IpTablesRule> rulesNew = new List<IpTablesRule>()
                                               {
                                                   IpTablesRule.Parse("-A INPUT -p udp -j DROP -m connlimit --connlimit-above 10 -m comment --comment \"ID1\"",mock, out chain,1),
                                                   IpTablesRule.Parse("-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2 -m comment --comment \"ID2\"",mock, out chain,2)
                                               };

            List<String> expectedCommands = new List<String>()
                                            {
                                                rulesNew[0].GetFullCommand("INPUT", "-R")
                                            };

            mock.TestSync(rulesOriginal, rulesNew, expectedCommands, mock, CommentComparer);
        }

        [Test]
        public void TestUpdateMiddle()
        {
            var mock = new MockIptablesSystemFactory();
            string chain;
            List<IpTablesRule> rulesOriginal = new List<IpTablesRule>()
                                               {
                                                   IpTablesRule.Parse("-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10 -m comment --comment \"ID1\"",mock, out chain,1),
                                                   IpTablesRule.Parse("-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2 -m comment --comment \"ID2\"",mock, out chain,2),
                                                   IpTablesRule.Parse("-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2 -m comment --comment \"ID3\"",mock, out chain,3)
                                               };
            List<IpTablesRule> rulesNew = new List<IpTablesRule>()
                                               {
                                                   IpTablesRule.Parse("-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10 -m comment --comment \"ID1\"",mock, out chain,1),
                                                   IpTablesRule.Parse("-A INPUT -p udp -j DROP -m connlimit --connlimit-above 28 -m comment --comment \"ID2\"",mock, out chain,2),
                                                   IpTablesRule.Parse("-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2 -m comment --comment \"ID3\"",mock, out chain,3)
                                               };

            List<String> expectedCommands = new List<String>()
                                            {
                                                rulesNew[1].GetFullCommand("INPUT", "-R")
                                            };

            mock.TestSync(rulesOriginal, rulesNew, expectedCommands, mock, CommentComparer);
        }
    }
}
