using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using IPTables.Net.Iptables.IpSet;
using IPTables.Net.Iptables.IpSet.Adapter;
using IPTables.Net.TestFramework;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    class IpSetSyncTests
    {
        [Test]
        public void TestSyncCreate()
        {
            var systemFactory = new MockIpsetSystemFactory();
            var system = new MockIpsetBinaryAdapter(systemFactory);
            var iptables = new IpTablesSystem(systemFactory, null, system);

            IpSetSets rulesOriginal = new IpSetSets(new List<String>()
            {
            }, iptables);

            system.SetSets(rulesOriginal);

            IpSetSets rulesNew = new IpSetSets(new List<String>()
            {
                "create test hash:ip",
                "add test 8.8.8.8"
            }, iptables);

            systemFactory.TestSync(rulesNew, new List<string>
            {
                "create test hash:ip family inet hashsize 1024 maxelem 65536",
                "add test 8.8.8.8"
            });
        }

        [Test]
        public void TestSyncDelete()
        {
            var systemFactory = new MockIpsetSystemFactory();
            var system = new MockIpsetBinaryAdapter(systemFactory);
            var iptables = new IpTablesSystem(systemFactory, null, system);

            IpSetSets rulesOriginal = new IpSetSets(new List<String>()
            {
                "create test hash:ip",
                "add test 8.8.8.8"
            }, iptables);

            system.SetSets(rulesOriginal);

            IpSetSets rulesNew = new IpSetSets(new List<String>()
            {
            }, iptables);

            systemFactory.TestSync(rulesNew, new List<string>
            {
                "destroy test"
            });
        }

        [Test]
        public void TestSyncEntryAdd()
        {
            var systemFactory = new MockIpsetSystemFactory();
            var system = new MockIpsetBinaryAdapter(systemFactory);
            var iptables = new IpTablesSystem(systemFactory, null, system);

            IpSetSets rulesOriginal = new IpSetSets(new List<String>()
            {
                "create test hash:ip"
            }, iptables);

            system.SetSets(rulesOriginal);

            IpSetSets rulesNew = new IpSetSets(new List<String>()
            {
                "create test hash:ip",
                "add test 8.8.8.8"
            }, iptables);

            systemFactory.TestSync(rulesNew, new List<string>
            {
                "add test 8.8.8.8"
            });
        }

        [Test]
        public void TestSyncEntryDelete()
        {
            var systemFactory = new MockIpsetSystemFactory();
            var system = new MockIpsetBinaryAdapter(systemFactory);
            var iptables = new IpTablesSystem(systemFactory, null, system);

            IpSetSets rulesOriginal = new IpSetSets(new List<String>()
            {
                "create test hash:ip",
                "add test 8.8.8.8"
            }, iptables);

            system.SetSets(rulesOriginal);

            IpSetSets rulesNew = new IpSetSets(new List<String>()
            {
                "create test hash:ip"
            }, iptables);

            systemFactory.TestSync(rulesNew, new List<string>
            {
                "del test 8.8.8.8"
            });
        }

        [Test]
        public void TestSyncEntryNotValues()
        {
            var systemFactory = new MockIpsetSystemFactory();
            var system = new MockIpsetBinaryAdapter(systemFactory);
            var iptables = new IpTablesSystem(systemFactory, null, system);

            IpSetSets rulesOriginal = new IpSetSets(new List<String>()
            {
                "create test hash:ip family inet hashsize 1024 maxelem 65536",
                "add test 8.8.8.8"
            }, iptables);


            system.SetSets(rulesOriginal);

            IpSetSets rulesNew = new IpSetSets(new List<String>()
            {
                "create test hash:ip"
            }, iptables);

            rulesNew.Sets.FirstOrDefault().SyncMode = IpSetSyncMode.SetOnly;

            systemFactory.TestSync(rulesNew, new List<string>
            {
            });
        }

        [Test]
        public void TestBitmapPort()
        {
            var systemFactory = new MockIpsetSystemFactory();
            var system = new MockIpsetBinaryAdapter(systemFactory);
            var iptables = new IpTablesSystem(systemFactory, null, system);

            IpSetSets rulesOriginal = new IpSetSets(new List<String>()
            {
                "create test bitmap:port family inet",
                "add test 80"
            }, iptables);


            system.SetSets(rulesOriginal);

            IpSetSets rulesNew = new IpSetSets(new List<String>()
            {
                "create test bitmap:port"
            }, iptables);

            rulesNew.Sets.FirstOrDefault().SyncMode = IpSetSyncMode.SetOnly;

            systemFactory.TestSync(rulesNew, new List<string>
            {
            });
        }

        [Test]
        public void TestBitmapPortNoChange()
        {
            var systemFactory = new MockIpsetSystemFactory();
            var system = new MockIpsetBinaryAdapter(systemFactory);
            var iptables = new IpTablesSystem(systemFactory, null, system);

            IpSetSets rulesOriginal = new IpSetSets(new List<String>()
            {
                "create test bitmap:port range 1-65535",
                "add test 80",
                "add test 81"
            }, iptables);

            rulesOriginal.Sets.FirstOrDefault().SyncMode = IpSetSyncMode.SetAndEntries;


            system.SetSets(rulesOriginal);

            IpSetSets rulesNew = new IpSetSets(new List<String>()
            {
                "create test bitmap:port range 1-65535",
                "add test 81",
                "add test 80"
            }, iptables);

            rulesNew.Sets.FirstOrDefault().SyncMode = IpSetSyncMode.SetAndEntries;

            systemFactory.TestSync(rulesNew, new List<string>
            {
            });
        }

        [Test]
        public void TestSyncCreateNet()
        {
            var systemFactory = new MockIpsetSystemFactory();
            var system = new MockIpsetBinaryAdapter(systemFactory);
            var iptables = new IpTablesSystem(systemFactory, null, system);

            IpSetSets rulesOriginal = new IpSetSets(new List<String>()
            {
            }, iptables);

            system.SetSets(rulesOriginal);

            IpSetSets rulesNew = new IpSetSets(new List<String>()
            {
                "create test hash:net",
                "add test 8.8.8.8/32"
            }, iptables);

            systemFactory.TestSync(rulesNew, new List<string>
            {
                "create test hash:net family inet hashsize 1024 maxelem 65536",
                "add test 8.8.8.8"
            });
        }
    }
}
