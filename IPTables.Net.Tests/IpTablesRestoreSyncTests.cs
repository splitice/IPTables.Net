using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Adapter;
using IPTables.Net.Iptables.Modules.Comment;
using IPTables.Net.Netfilter;
using IPTables.Net.Tests.MockSystem;
using IPTables.Net.Tests.MockSystem.IpTablesRestore;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    class IpTablesRestoreSyncTests
    {
        [Test]
        public void TestQuotes()
        {
            var mock = new MockIptablesSystemFactory();
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());
            IpTablesRuleSet rulesOriginal = new IpTablesRuleSet(4,new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP",
                                               }, system);
            IpTablesRuleSet rulesNew = new IpTablesRuleSet(4,new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP",
                                                   "-A INPUT -m comment --comment 'test space'"
                                               }, system);

            List<String> expectedCommands = new List<String> { "*filter", 
                                                   "-A INPUT -m comment --comment \"test space\"", "COMMIT" };

            mock.TestSync(rulesOriginal, rulesNew);
            var output = (system.GetTableAdapter(4) as MockIpTablesRestoreAdapterClient).GetOutput();
            CollectionAssert.AreEqual(output, expectedCommands);
        }

        [Test]
        public void TestAdd()
        {
            var mock = new MockIptablesSystemFactory();
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());
            IpTablesRuleSet rulesOriginal = new IpTablesRuleSet(4,new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2"
                                               }, system);
            IpTablesRuleSet rulesNew = new IpTablesRuleSet(4,new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2",
                                                   "-A INPUT -d 1.2.3.4/16 -j DROP"
                                               }, system);

            List<String> expectedCommands = new List<String> { "*filter", rulesNew.Chains.First().Rules[2].GetActionCommand(), "COMMIT" };

            mock.TestSync(rulesOriginal, rulesNew);
            CollectionAssert.AreEqual((system.GetTableAdapter(4) as MockIpTablesRestoreAdapterClient).GetOutput(), expectedCommands);
        }

        [Test]
        public void TestSimpleDoNothing()
        {
            var mock = new MockIptablesSystemFactory();
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());
            IpTablesRuleSet rulesOriginal = new IpTablesRuleSet(4,new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2"
                                               }, system);
            IpTablesRuleSet rulesNew = new IpTablesRuleSet(4,new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2"
                                               }, system);

            List<String> expectedCommands = new List<String>() {};

            mock.TestSync(rulesOriginal, rulesNew);
            CollectionAssert.AreEqual((system.GetTableAdapter(4) as MockIpTablesRestoreAdapterClient).GetOutput(), expectedCommands);
        }

        [Test]
        public void TestNatDoNothing()
        {
            var mock = new MockIptablesSystemFactory();
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());
            IpTablesRuleSet rulesOriginal = new IpTablesRuleSet(4,new List<String>()
                                               {
                                                   "-A PREROUTING -t nat -j DNAT -p tcp -m tcp --dport 80 --to-destination 99.99.99.99:80",
                                                   "-A PREROUTING -t nat -j SNAT --to-source 99.99.99.99:80"
                                               }, system);
            IpTablesRuleSet rulesNew = new IpTablesRuleSet(4,new List<String>()
                                               {
                                                   "-A PREROUTING -t nat -j DNAT -p tcp -m tcp --dport 80 --to-destination 99.99.99.99:80",
                                                   "-A PREROUTING -t nat -j SNAT --to-source 99.99.99.99:80"
                                               }, system);

            List<String> expectedCommands = new List<String>() { };

            mock.TestSync(rulesOriginal, rulesNew);
            CollectionAssert.AreEqual((system.GetTableAdapter(4) as MockIpTablesRestoreAdapterClient).GetOutput(), expectedCommands);
        }

        [Test]
        public void TestAddDuplicate()
        {
            var mock = new MockIptablesSystemFactory();
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());
            IpTablesRuleSet rulesOriginal = new IpTablesRuleSet(4,new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2",
                                               }, system);
            IpTablesRuleSet rulesNew = new IpTablesRuleSet(4,new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2",
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                                               }, system);

            List<String> expectedCommands = new List<String>() { "*filter", rulesNew.Chains.First().Rules[2].GetActionCommand(), "COMMIT" };

            mock.TestSync(rulesOriginal, rulesNew);
            CollectionAssert.AreEqual((system.GetTableAdapter(4) as MockIpTablesRestoreAdapterClient).GetOutput(), expectedCommands); ;
        }

        [Test]
        public void TestDelete()
        {
            var mock = new MockIptablesSystemFactory();
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());

            IpTablesRuleSet rulesOriginal = new IpTablesRuleSet(4,new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2"
                                               }, system);
            IpTablesRuleSet rulesNew = new IpTablesRuleSet(4,new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                                               }, system);

            List<String> expectedCommands = new List<String>() { "*filter", "-D INPUT 2", "COMMIT" };

            mock.TestSync(rulesOriginal, rulesNew);
            CollectionAssert.AreEqual((system.GetTableAdapter(4) as MockIpTablesRestoreAdapterClient).GetOutput(), expectedCommands); ;
        }

        [Test]
        public void TestDeleteMultiples()
        {
            var mock = new MockIptablesSystemFactory();
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());

            IpTablesRuleSet rulesOriginal = new IpTablesRuleSet(4,new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 5",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2"
                                               }, system);
            IpTablesRuleSet rulesNew = new IpTablesRuleSet(4,new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 5"
                                               }, system);

            List<String> expectedCommands = new List<String>() { "*filter", "-D INPUT 1", "-D INPUT 2", "COMMIT" };

            mock.TestSync(rulesOriginal, rulesNew);
            CollectionAssert.AreEqual((system.GetTableAdapter(4) as MockIpTablesRestoreAdapterClient).GetOutput(), expectedCommands);
        }

        [Test]
        public void TestInsertMiddle()
        {
            var mock = new MockIptablesSystemFactory();
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());

            IpTablesRuleSet rulesOriginal = new IpTablesRuleSet(4,new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2"
                                               }, system);
            IpTablesRuleSet rulesNew = new IpTablesRuleSet(4,new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 5",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2"
                                               }, system);

            List<String> expectedCommands = new List<String>()
                                            {
                                                "*filter", 
                                                "-D INPUT 2",
                                                rulesNew.Chains.First().Rules[1].GetActionCommand(),
                                                rulesNew.Chains.First().Rules[2].GetActionCommand(), "COMMIT" };

            mock.TestSync(rulesOriginal, rulesNew);
            CollectionAssert.AreEqual((system.GetTableAdapter(4) as MockIpTablesRestoreAdapterClient).GetOutput(), expectedCommands);
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
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());

            IpTablesRuleSet rulesOriginal = new IpTablesRuleSet(4,new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10 -m comment --comment \"ID1\"",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2 -m comment --comment \"ID2\""
                                               }, system);
            IpTablesRuleSet rulesNew = new IpTablesRuleSet(4,new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10 -m comment --comment \"ID1\"",
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 5 -m comment --comment \"ID2\"",
                                               }, system);

            List<String> expectedCommands = new List<String>()
                                            {
                                                "*filter", rulesNew.Chains.First().Rules[1].GetActionCommand("-R"), "COMMIT" };

            mock.TestSync(rulesOriginal, rulesNew, CommentComparer);
            CollectionAssert.AreEqual((system.GetTableAdapter(4) as MockIpTablesRestoreAdapterClient).GetOutput(), expectedCommands);
        }

        [Test]
        public void TestUpdateBegin()
        {
            var mock = new MockIptablesSystemFactory();
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());

            IpTablesRuleSet rulesOriginal = new IpTablesRuleSet(4,new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10 -m comment --comment \"ID1\"",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2 -m comment --comment \"ID2\""
                                               }, system);
            IpTablesRuleSet rulesNew = new IpTablesRuleSet(4,new List<String>()
                                               {
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 10 -m comment --comment \"ID1\"",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2 -m comment --comment \"ID2\""
                                               }, system);

            List<String> expectedCommands = new List<String>()
                                            {
                                                "*filter", rulesNew.Chains.First().Rules[0].GetActionCommand("-R"), "COMMIT" };

            mock.TestSync(rulesOriginal, rulesNew, CommentComparer);
            CollectionAssert.AreEqual((system.GetTableAdapter(4) as MockIpTablesRestoreAdapterClient).GetOutput(), expectedCommands);
        }

        [Test]
        public void TestUpdateMiddle()
        {
            var mock = new MockIptablesSystemFactory();
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());

            IpTablesRuleSet rulesOriginal = new IpTablesRuleSet(4,new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10 -m comment --comment \"ID1\"",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2 -m comment --comment \"ID2\"",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2 -m comment --comment \"ID3\""
                                               }, system);
            IpTablesRuleSet rulesNew = new IpTablesRuleSet(4,new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10 -m comment --comment \"ID1\"",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 28 -m comment --comment \"ID2\"",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2 -m comment --comment \"ID3\""
                                               }, system);

            List<String> expectedCommands = new List<String>()
                                            {
                                                "*filter", rulesNew.Chains.First().Rules[1].GetActionCommand("-R"), "COMMIT" };

            mock.TestSync(rulesOriginal, rulesNew, CommentComparer);
            CollectionAssert.AreEqual((system.GetTableAdapter(4) as MockIpTablesRestoreAdapterClient).GetOutput(), expectedCommands);
        }
    }
}
