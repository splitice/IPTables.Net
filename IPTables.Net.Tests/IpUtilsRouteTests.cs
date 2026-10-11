using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using IPTables.Net.IpUtils;
using IPTables.Net.IpUtils.Utils;
using IPTables.Net.TestFramework;

namespace IPTables.Net.Tests
{
    public class IpUtilsRouteTests
    {
        [Fact]
        public void TestParseRule()
        {
            var systemFactory = new MockIptablesSystemFactory();
            var ipUtils = new IpRouteController(systemFactory);
            var one = ipUtils.ParseObjectInternal("default via 199.19.225.1 dev eth0", "to");
            var two = ipUtils.ParseObjectInternal("10.128.1.0/24 dev tap0  proto kernel  scope link  src 10.128.1.201", "to");
            Assert.Equal("default", one.Pairs["to"]); Assert.Equal("199.19.225.1", one.Pairs["via"]);
            Assert.Equal("eth0", one.Pairs["dev"]); Assert.Equal("10.128.1.0/24", two.Pairs["to"]);
            Assert.Equal("tap0", two.Pairs["dev"]); Assert.Equal("10.128.1.201", two.Pairs["src"]);

        }
        [Fact]
        public void TestParseRuleLocal()
        {
            var systemFactory = new MockIptablesSystemFactory();
            var ipUtils = new IpRouteController(systemFactory);
            var one = ipUtils.ParseObjectInternal("local default dev lo  table 100  scope host", "to");
            Assert.Equal("local default dev lo table 100 scope host", string.Join(" ", ipUtils.ExportObject(one)));
        }
        [Fact]
        public void TestParseRuleAnycastV6()
        {
            var systemFactory = new MockIptablesSystemFactory();
            var ipUtils = new IpRouteController(systemFactory);
            var one = ipUtils.ParseObjectInternal("anycast fe80:: dev tap0 table local proto kernel metric 0 pref medium", "to");
            Assert.Equal("fe80:: dev tap0 table local proto kernel metric 0 pref medium anycast", string.Join(" ", ipUtils.ExportObject(one)));
        }
    }
}
