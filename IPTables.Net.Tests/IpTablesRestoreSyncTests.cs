using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Adapter;
using IPTables.Net.Iptables.Modules.Comment;
using IPTables.Net.Netfilter;
using IPTables.Net.Netfilter.TableSync;
using IPTables.Net.TestFramework;
using IPTables.Net.TestFramework.IpTablesRestore;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    class IpTablesRestoreSyncTests
    {
        internal void TestApply(IpTablesRuleSet rulesOrig, IpTablesRuleSet rulesSynced, IpTablesRuleSet rulesNew, List<string> commands)
        {
            try
            {
                Assert.AreEqual(rulesNew, rulesSynced);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Sync:");
                DumpRuleset(rulesSynced);
                Console.WriteLine("New:");
                DumpRuleset(rulesNew);
                throw;
            }


            String currentTable = "filter";
            foreach (var cmd in commands)
            {
                if (cmd.StartsWith("*"))
                {
                    currentTable = cmd.Substring(1);
                    continue;
                }
                if (!cmd.StartsWith("-")) continue;
                var ipCmd = IpTablesCommand.Parse(cmd, rulesOrig.System, rulesOrig.Chains, rulesOrig.IpVersion, currentTable);
                
                if (ipCmd.Rule != null)
                {
                    ipCmd.Rule.Chain = rulesOrig.Chains.GetChain(ipCmd.ChainName, ipCmd.Table);
                }

                rulesOrig.ApplyCommand(ipCmd);
            }

            try
            {
                Assert.AreEqual(rulesNew, rulesOrig);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Orig:");
                DumpRuleset(rulesOrig);
                Console.WriteLine("New:");
                DumpRuleset(rulesNew);
                throw;
            }
        }

        private void DumpRuleset(IpTablesRuleSet rulesOrig)
        {
            foreach (var r in rulesOrig.Rules)
            {
                Console.WriteLine(r.GetActionCommand());
            }
        }

        [Test]
        public void TestQuotes()
        {
            var mock = new MockIptablesSystemFactory();
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());
            IpTablesRuleSet rulesOriginal = new IpTablesRuleSet(4, new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP",
                                               }, system);
            IpTablesRuleSet rulesNew = new IpTablesRuleSet(4, new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP",
                                                   "-A INPUT -m comment --comment 'test space'"
                                               }, system);

            List<String> expectedCommands = new List<String> { "*filter", 
                                                   "-A INPUT -m comment --comment \"test space\"", "COMMIT" };


            using (var client = system.GetTableAdapter(4))
            {
                var sync = new DefaultNetfilterSync<IpTablesRule>();
                var rulesSynced = rulesOriginal.DeepClone();
                mock.TestSync(client, rulesSynced, rulesNew, sync);
                CollectionAssert.AreEqual(expectedCommands, (client as IMockIpTablesRestoreGetOutput).GetOutput());

                TestApply(rulesOriginal, rulesSynced, rulesNew, expectedCommands);
            }
        }

        [Test]
        public void TestAdd()
        {
            var mock = new MockIptablesSystemFactory();
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());
            IpTablesRuleSet rulesOriginal = new IpTablesRuleSet(4, new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2"
                                               }, system);
            IpTablesRuleSet rulesNew = new IpTablesRuleSet(4, new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2",
                                                   "-A INPUT -d 1.2.3.4/16 -j DROP"
                                               }, system);

            List<String> expectedCommands = new List<String> { "*filter", rulesNew.Chains.First().Rules[2].GetActionCommand(), "COMMIT" };


            using (var client = system.GetTableAdapter(4))
            {
                var sync = new DefaultNetfilterSync<IpTablesRule>();
                var rulesSynced = rulesOriginal.DeepClone();
                mock.TestSync(client, rulesSynced, rulesNew, sync);
                CollectionAssert.AreEqual(expectedCommands, (client as IMockIpTablesRestoreGetOutput).GetOutput());

                TestApply(rulesOriginal, rulesSynced, rulesNew, expectedCommands);
            }
        }

        [Test]
        public void TestSimpleDoNothing()
        {
            var mock = new MockIptablesSystemFactory();
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());
            IpTablesRuleSet rulesOriginal = new IpTablesRuleSet(4, new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2"
                                               }, system);
            IpTablesRuleSet rulesNew = new IpTablesRuleSet(4, new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2"
                                               }, system);

            List<String> expectedCommands = new List<String>() { };


            using (var client = system.GetTableAdapter(4))
            {
                var sync = new DefaultNetfilterSync<IpTablesRule>();
                var rulesSynced = rulesOriginal.DeepClone();
                mock.TestSync(client, rulesSynced, rulesNew, sync);
                CollectionAssert.AreEqual(expectedCommands, (client as IMockIpTablesRestoreGetOutput).GetOutput());

                TestApply(rulesOriginal, rulesSynced, rulesNew, expectedCommands);
            }
        }

        [Test]
        public void TestNatDoNothing()
        {
            var mock = new MockIptablesSystemFactory();
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());
            IpTablesRuleSet rulesOriginal = new IpTablesRuleSet(4, new List<String>()
                                               {
                                                   "-A PREROUTING -t nat -j DNAT -p tcp -m tcp --dport 80 --to-destination 99.99.99.99:80",
                                                   "-A PREROUTING -t nat -j SNAT --to-source 99.99.99.99:80"
                                               }, system);
            IpTablesRuleSet rulesNew = new IpTablesRuleSet(4, new List<String>()
                                               {
                                                   "-A PREROUTING -t nat -j DNAT -p tcp -m tcp --dport 80 --to-destination 99.99.99.99:80",
                                                   "-A PREROUTING -t nat -j SNAT --to-source 99.99.99.99:80"
                                               }, system);

            List<String> expectedCommands = new List<String>() { };


            using (var client = system.GetTableAdapter(4))
            {
                var sync = new DefaultNetfilterSync<IpTablesRule>();
                var rulesSynced = rulesOriginal.DeepClone();
                mock.TestSync(client, rulesSynced, rulesNew, sync);
                CollectionAssert.AreEqual(expectedCommands, (client as IMockIpTablesRestoreGetOutput).GetOutput());

                TestApply(rulesOriginal, rulesSynced, rulesNew, expectedCommands);
            }
        }

        [Test]
        public void TestAddDuplicate()
        {
            var mock = new MockIptablesSystemFactory();
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());
            IpTablesRuleSet rulesOriginal = new IpTablesRuleSet(4, new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2",
                                               }, system);
            IpTablesRuleSet rulesNew = new IpTablesRuleSet(4, new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2",
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                                               }, system);

            List<String> expectedCommands = new List<String>() { "*filter", rulesNew.Chains.First().Rules[2].GetActionCommand(), "COMMIT" };


            using (var client = system.GetTableAdapter(4))
            {
                var sync = new DefaultNetfilterSync<IpTablesRule>();
                var rulesSynced = rulesOriginal.DeepClone();
                mock.TestSync(client, rulesSynced, rulesNew, sync);
                CollectionAssert.AreEqual(expectedCommands, (client as IMockIpTablesRestoreGetOutput).GetOutput());

                TestApply(rulesOriginal, rulesSynced, rulesNew, expectedCommands);
            }
        }

        [Test]
        public void TestDelete()
        {
            var mock = new MockIptablesSystemFactory();
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());

            IpTablesRuleSet rulesOriginal = new IpTablesRuleSet(4, new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2"
                                               }, system);
            IpTablesRuleSet rulesNew = new IpTablesRuleSet(4, new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                                               }, system);

            List<String> expectedCommands = new List<String>() { "*filter", "-D INPUT 2", "COMMIT" };

            using (var client = system.GetTableAdapter(4))
            {
                var sync = new DefaultNetfilterSync<IpTablesRule>();
                var rulesSynced = rulesOriginal.DeepClone();
                mock.TestSync(client, rulesSynced, rulesNew, sync);
                CollectionAssert.AreEqual(expectedCommands, (client as IMockIpTablesRestoreGetOutput).GetOutput());

                TestApply(rulesOriginal, rulesSynced, rulesNew, expectedCommands);
            }
        }

        [Test]
        public void TestDeleteMultiplesStart()
        {
            var mock = new MockIptablesSystemFactory();
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());

            IpTablesRuleSet rulesOriginal = new IpTablesRuleSet(4, new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 5",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2"
                                               }, system);
            IpTablesRuleSet rulesNew = new IpTablesRuleSet(4, new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10"
                                               }, system);

            List<String> expectedCommands = new List<String>() { "*filter", "-D INPUT 2", "-D INPUT 2", "COMMIT" };

            using (var client = system.GetTableAdapter(4))
            {
                var sync = new DefaultNetfilterSync<IpTablesRule>();
                mock.TestSync(client, rulesOriginal, rulesNew, sync);
                CollectionAssert.AreEqual(expectedCommands, (client as IMockIpTablesRestoreGetOutput).GetOutput());
            }
        }

        [Test]
        public void TestDeleteMultiplesEnd()
        {
            var mock = new MockIptablesSystemFactory();
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());

            IpTablesRuleSet rulesOriginal = new IpTablesRuleSet(4, new List<String>()
            {
                "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 5",
                "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2"
            }, system);
            IpTablesRuleSet rulesNew = new IpTablesRuleSet(4, new List<String>()
            {
                "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2"
            }, system);

            List<String> expectedCommands = new List<String>() { "*filter", "-D INPUT 1", "-D INPUT 1", "COMMIT" };


            using (var client = system.GetTableAdapter(4))
            {
                var sync = new DefaultNetfilterSync<IpTablesRule>();
                var rulesSynced = rulesOriginal.DeepClone();
                mock.TestSync(client, rulesSynced, rulesNew, sync);
                CollectionAssert.AreEqual(expectedCommands, (client as IMockIpTablesRestoreGetOutput).GetOutput());

                TestApply(rulesOriginal, rulesSynced, rulesNew, expectedCommands);
            }
        }


        [Test]
        public void TestDeleteMultiplesMiddle()
        {
            var mock = new MockIptablesSystemFactory();
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());

            IpTablesRuleSet rulesOriginal = new IpTablesRuleSet(4, new List<String>()
            {
                "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 5",
                "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2",
                "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 3"
            }, system);
            IpTablesRuleSet rulesNew = new IpTablesRuleSet(4, new List<String>()
            {
                "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 3"
            }, system);

            List<String> expectedCommands = new List<String>() { "*filter", "-D INPUT 2", "-D INPUT 2", "COMMIT" };


            using (var client = system.GetTableAdapter(4))
            {
                var sync = new DefaultNetfilterSync<IpTablesRule>();
                var rulesSynced = rulesOriginal.DeepClone();
                mock.TestSync(client, rulesSynced, rulesNew, sync);
                CollectionAssert.AreEqual(expectedCommands, (client as IMockIpTablesRestoreGetOutput).GetOutput());

                TestApply(rulesOriginal, rulesSynced, rulesNew, expectedCommands);
            }
        }


        [Test]
        public void TestDeleteMultiplesMiddleSplit()
        {
            var mock = new MockIptablesSystemFactory();
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());

            IpTablesRuleSet rulesOriginal = new IpTablesRuleSet(4, new List<String>()
            {
                "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 5",
                "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 1",
                "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2",
                "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 3"
            }, system);
            IpTablesRuleSet rulesNew = new IpTablesRuleSet(4, new List<String>()
            {
                "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 1",
                "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 3"
            }, system);

            List<String> expectedCommands = new List<String>() { "*filter", "-D INPUT 2", "-D INPUT 3", "COMMIT" };


            using (var client = system.GetTableAdapter(4))
            {
                var sync = new DefaultNetfilterSync<IpTablesRule>();
                var rulesSynced = rulesOriginal.DeepClone();
                mock.TestSync(client, rulesSynced, rulesNew, sync);
                CollectionAssert.AreEqual(expectedCommands, (client as IMockIpTablesRestoreGetOutput).GetOutput());

                TestApply(rulesOriginal, rulesSynced, rulesNew, expectedCommands);
            }
        }



        [Test]
        public void TestInsertMiddle()
        {
            var mock = new MockIptablesSystemFactory();
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());

            IpTablesRuleSet rulesOriginal = new IpTablesRuleSet(4, new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2"
                                               }, system);
            IpTablesRuleSet rulesNew = new IpTablesRuleSet(4, new List<String>()
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
            List<String> commands;

            using (var client = system.GetTableAdapter(4))
            {
                var sync = new DefaultNetfilterSync<IpTablesRule>();
                var rulesSynced = rulesOriginal.DeepClone();
                mock.TestSync(client, rulesSynced, rulesNew, sync);
                CollectionAssert.AreEqual(expectedCommands, (client as IMockIpTablesRestoreGetOutput).GetOutput());

                TestApply(rulesOriginal, rulesSynced, rulesNew, expectedCommands);
            }
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

            IpTablesRuleSet rulesOriginal = new IpTablesRuleSet(4, new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10 -m comment --comment \"ID1\"",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2 -m comment --comment \"ID2\""
                                               }, system);
            IpTablesRuleSet rulesNew = new IpTablesRuleSet(4, new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10 -m comment --comment \"ID1\"",
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 5 -m comment --comment \"ID2\"",
                                               }, system);

            List<String> expectedCommands = new List<String>()
                                            {
                                                "*filter", rulesNew.Chains.First().Rules[1].GetActionCommand("-R"), "COMMIT" };


            using (var client = system.GetTableAdapter(4))
            {
                var sync = new DefaultNetfilterSync<IpTablesRule>();
                var rulesSynced = rulesOriginal.DeepClone();
                mock.TestSync(client, rulesSynced, rulesNew, sync);
                CollectionAssert.AreEqual(expectedCommands, (client as IMockIpTablesRestoreGetOutput).GetOutput());

                TestApply(rulesOriginal, rulesSynced, rulesNew, expectedCommands);
            }
        }

        [Test]
        public void TestUpdateBegin()
        {
            var mock = new MockIptablesSystemFactory();
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());

            IpTablesRuleSet rulesOriginal = new IpTablesRuleSet(4, new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10 -m comment --comment \"ID1\"",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2 -m comment --comment \"ID2\""
                                               }, system);
            IpTablesRuleSet rulesNew = new IpTablesRuleSet(4, new List<String>()
                                               {
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 10 -m comment --comment \"ID1\"",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2 -m comment --comment \"ID2\""
                                               }, system);

            List<String> expectedCommands = new List<String>()
                                            {
                                                "*filter", rulesNew.Chains.First().Rules[0].GetActionCommand("-R"), "COMMIT" };


            using (var client = system.GetTableAdapter(4))
            {
                var sync = new DefaultNetfilterSync<IpTablesRule>();
                var rulesSynced = rulesOriginal.DeepClone();
                mock.TestSync(client, rulesSynced, rulesNew, sync);
                CollectionAssert.AreEqual(expectedCommands, (client as IMockIpTablesRestoreGetOutput).GetOutput());

                TestApply(rulesOriginal, rulesSynced, rulesNew, expectedCommands);
            }
        }

        [Test]
        public void TestUpdateMiddle()
        {
            var mock = new MockIptablesSystemFactory();
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());

            IpTablesRuleSet rulesOriginal = new IpTablesRuleSet(4, new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10 -m comment --comment \"ID1\"",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2 -m comment --comment \"ID2\"",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2 -m comment --comment \"ID3\""
                                               }, system);
            IpTablesRuleSet rulesNew = new IpTablesRuleSet(4, new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10 -m comment --comment \"ID1\"",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 28 -m comment --comment \"ID2\"",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2 -m comment --comment \"ID3\""
                                               }, system);

            List<String> expectedCommands = new List<String>()
                                            {
                                                "*filter", rulesNew.Chains.First().Rules[1].GetActionCommand("-R"), "COMMIT" };


            using (var client = system.GetTableAdapter(4))
            {
                var sync = new DefaultNetfilterSync<IpTablesRule>();
                var rulesSynced = rulesOriginal.DeepClone();
                mock.TestSync(client, rulesSynced, rulesNew, sync);
                CollectionAssert.AreEqual(expectedCommands, (client as IMockIpTablesRestoreGetOutput).GetOutput());

                TestApply(rulesOriginal, rulesSynced, rulesNew, expectedCommands);
            }
        }

        [Test]
        public void TestUpdateUnlabelled()
        {
            var mock = new MockIptablesSystemFactory();
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());

            IpTablesRuleSet rulesOriginal = new IpTablesRuleSet(4, new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2"
                                               }, system);
            IpTablesRuleSet rulesNew = new IpTablesRuleSet(4, new List<String>()
                                               {
                                                   "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 28",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 11",
                                                   "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2"
                                               }, system);

            List<String> expectedCommands = new List<String>
                                            {
                                                "*filter", rulesNew.Chains.First().Rules[1].GetActionCommand("-R"), rulesNew.Chains.First().Rules[2].GetActionCommand("-R"), "COMMIT"
                                            };


            using (var client = system.GetTableAdapter(4))
            {
                var sync = new DefaultNetfilterSync<IpTablesRule>();
                var rulesSynced = rulesOriginal.DeepClone();
                mock.TestSync(client, rulesSynced, rulesNew, sync);
                var output = (client as IMockIpTablesRestoreGetOutput).GetOutput();
                CollectionAssert.AreEqual(expectedCommands, output);

                TestApply(rulesOriginal, rulesSynced, rulesNew, expectedCommands);
            }
        }


        [Test]
        public void TestUpdateMiddleTwo()
        {
            var mock = new MockIptablesSystemFactory();
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());

            IpTablesRuleSet rulesOriginal = new IpTablesRuleSet(4, new List<String>()
            {
                "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10 -m comment --comment \"ID1\"",
                "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2 -m comment --comment \"ID2\"",
                "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2 -m comment --comment \"ID3\"",
                "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2 -m comment --comment \"ID4\""
            }, system);
            IpTablesRuleSet rulesNew = new IpTablesRuleSet(4, new List<String>()
            {
                "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10 -m comment --comment \"ID1\"",
                "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 28 -m comment --comment \"ID2\"",
                "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 1 -m comment --comment \"ID3\"",
                "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2 -m comment --comment \"ID4\""
            }, system);

            List<String> expectedCommands = new List<String>()
            {
                "*filter",
                rulesNew.Chains.First().Rules[1].GetActionCommand("-R"),
                rulesNew.Chains.First().Rules[2].GetActionCommand("-R"),
                "COMMIT"
            };


            using (var client = system.GetTableAdapter(4))
            {
                var sync = new DefaultNetfilterSync<IpTablesRule>();
                var rulesSynced = rulesOriginal.DeepClone();
                mock.TestSync(client, rulesSynced, rulesNew, sync);
                CollectionAssert.AreEqual(expectedCommands, (client as IMockIpTablesRestoreGetOutput).GetOutput());

                TestApply(rulesOriginal, rulesSynced, rulesNew, expectedCommands);
            }
        }


        [Test]
        public void TestDeleteAndUpdate()
        {
            var mock = new MockIptablesSystemFactory();
            var system = new IpTablesSystem(mock, new MockIpTablesRestoreAdapter());

            IpTablesRuleSet rulesOriginal = new IpTablesRuleSet(4, new List<String>()
            {
                "-A INPUT -p tcp -j DROP -m connlimit --connlimit-above 10 -m comment --comment \"ID1\"",
                "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2 -m comment --comment \"ID2\"",
                "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2 -m comment --comment \"ID3\"",
                "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2 -m comment --comment \"ID4\""
            }, system);
            IpTablesRuleSet rulesNew = new IpTablesRuleSet(4, new List<String>()
            {
                "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 28 -m comment --comment \"ID2\"",
                "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 1 -m comment --comment \"ID3\"",
                "-A INPUT -p udp -j DROP -m connlimit --connlimit-above 2 -m comment --comment \"ID4\""
            }, system);
            

            using (var client = system.GetTableAdapter(4))
            {
                var sync = new DefaultNetfilterSync<IpTablesRule>(CommentComparer);
                mock.TestSync(client, rulesOriginal, rulesNew, sync);
                var commands = (client as IMockIpTablesRestoreGetOutput).GetOutput().ToList();
                Assert.AreEqual(5, commands.Count);
                Assert.True(commands[1].StartsWith("-D INPUT 1"));
                Assert.True(commands[2].StartsWith("-R INPUT 1"));
                Assert.True(commands[3].StartsWith("-R INPUT 2"));
            }
        }
    }
}
