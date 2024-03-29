﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using IPTables.Net.IpSet;
using IPTables.Net.TestFramework;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    class IpSetCidrTests
    {
        [Test]
        public void TestSyncCreateLarger()
        {
            var systemFactory = new MockIpsetSystemFactory();
            var system = new MockIpsetBinaryAdapter(systemFactory);
            var iptables = new IpTablesSystem(systemFactory, null, system);

            IpSetSets rulesOriginal = new IpSetSets(new List<String>()
            {
                "create test hash:ip",
                "add test 8.8.8.0"
            }, iptables);

            system.SetSets(rulesOriginal);

            IpSetSets rulesNew = new IpSetSets(new List<String>()
            {
                "create test hash:ip",
                "add test 8.8.8.0/30"
            }, iptables);

            systemFactory.TestSync(rulesNew, new List<string>
            {
                "del test 8.8.8.0",
                "add test 8.8.8.0/30"
            });
        }

        [Test]
        public void TestSyncLargerIsTheSame()
        {
            var systemFactory = new MockIpsetSystemFactory();
            var system = new MockIpsetBinaryAdapter(systemFactory);
            var iptables = new IpTablesSystem(systemFactory, null, system);

            IpSetSets rulesOriginal = new IpSetSets(new List<String>()
            {
                "create test hash:ip",
                "add test 8.8.8.0",
                "add test 8.8.8.1"
            }, iptables);

            system.SetSets(rulesOriginal);

            IpSetSets rulesNew = new IpSetSets(new List<String>()
            {
                "create test hash:ip",
                "add test 8.8.8.0/31"
            }, iptables);

            systemFactory.TestSync(rulesNew, new List<string>
            {
            });
        }
        [Test]
        public void TestSyncCreateSmaller()
        {
            var systemFactory = new MockIpsetSystemFactory();
            var system = new MockIpsetBinaryAdapter(systemFactory);
            var iptables = new IpTablesSystem(systemFactory, null, system);

            IpSetSets rulesOriginal = new IpSetSets(new List<String>()
            {
                "create test hash:ip",
                "add test 8.8.8.0/24"
            }, iptables);

            system.SetSets(rulesOriginal);

            IpSetSets rulesNew = new IpSetSets(new List<String>()
            {
                "create test hash:ip",
                "add test 8.8.8.0/30"
            }, iptables);

            systemFactory.TestSync(rulesNew, new List<string>
            {
                "del test 8.8.8.0/24",
                "add test 8.8.8.0/30"
            });
        }

        [Test]
        public void TestSyncCreateMultipleLarger()
        {
            var systemFactory = new MockIpsetSystemFactory();
            var system = new MockIpsetBinaryAdapter(systemFactory);
            var iptables = new IpTablesSystem(systemFactory, null, system);

            IpSetSets rulesOriginal = new IpSetSets(new List<String>()
            {
                "create test hash:ip",
                "add test 8.8.8.0/24",
                "add test 8.8.7.0/24"
            }, iptables);

            system.SetSets(rulesOriginal);

            IpSetSets rulesNew = new IpSetSets(new List<String>()
            {
                "create test hash:ip",
                "add test 8.8.0.0/16"
            }, iptables);

            systemFactory.TestSync(rulesNew, new List<string>
            {
                "del test 8.8.8.0/24",
                "del test 8.8.7.0/24",
                "add test 8.8.0.0/16"
            });
        }
        [Test]
        public void TestSyncCreateSmallerWithPort()
        {
            var systemFactory = new MockIpsetSystemFactory();
            var system = new MockIpsetBinaryAdapter(systemFactory);
            var iptables = new IpTablesSystem(systemFactory, null, system);

            IpSetSets rulesOriginal = new IpSetSets(new List<String>()
            {
                "create test hash:ip,port",
                "add test 8.8.8.0/24,udp:123",
                "add test 8.8.8.0/24,udp:124"
            }, iptables);

            system.SetSets(rulesOriginal);

            IpSetSets rulesNew = new IpSetSets(new List<String>()
            {
                "create test hash:ip,port",
                "add test 8.8.8.0/30,udp:123"
            }, iptables);

            systemFactory.TestSync(rulesNew, new List<string>
            {
                "del test 8.8.8.0/24,udp:123",
                "del test 8.8.8.0/24,udp:124",
                "add test 8.8.8.0/30,udp:123"
            });
        }
        [Test]
        public void TestSyncNoChangeWithPort()
        {
            var systemFactory = new MockIpsetSystemFactory();
            var system = new MockIpsetBinaryAdapter(systemFactory);
            var iptables = new IpTablesSystem(systemFactory, null, system);

            IpSetSets rulesOriginal = new IpSetSets(new List<String>()
            {
                "create test hash:ip,port",
                "add test 8.8.8.0/24,udp:123",
                "add test 8.8.8.0/24,udp:124"
            }, iptables);

            system.SetSets(rulesOriginal);

            IpSetSets rulesNew = new IpSetSets(new List<String>()
            {
                "create test hash:ip,port",
                "add test 8.8.8.0/24,udp:123",
                "add test 8.8.8.0/24,udp:124"
            }, iptables);

            systemFactory.TestSync(rulesNew, new List<string>
            {
            });
        }
    }
}
