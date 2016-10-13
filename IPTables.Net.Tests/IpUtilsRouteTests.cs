using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using IPTables.Net.Iptables.IpSet;
using IPTables.Net.Iptables.IpSet.Adapter;
using IPTables.Net.IpUtils;
using IPTables.Net.IpUtils.Utils;
using IPTables.Net.TestFramework;
using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    class IpUtilsRouteTests
    {
        [Test]
        public void TestParseRule()
        {
            var systemFactory = new MockIptablesSystemFactory();
            var ipUtils = new IpRouteController(systemFactory);
            var one = ipUtils.ParseObjectInternal("default via 199.19.225.1 dev eth0", "to");
            var two = ipUtils.ParseObjectInternal("10.128.1.0/24 dev tap0  proto kernel  scope link  src 10.128.1.201", "to");

        }
        [Test]
        public void TestParseRuleLocal()
        {
            var systemFactory = new MockIptablesSystemFactory();
            var ipUtils = new IpRouteController(systemFactory);
            var one = ipUtils.ParseObjectInternal("local default dev lo  table 100  scope host", "to");
            ipUtils.ExportObject(one);
        }
    }
}
