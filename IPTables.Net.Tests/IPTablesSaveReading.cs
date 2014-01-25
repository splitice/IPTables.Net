﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using NUnit.Framework;

namespace IPTables.Net.Tests
{
    [TestFixture]
    class IPTablesSaveReading
    {
        private static readonly IPTablesSystem Processor = new IPTablesSystem(new ModuleFactory());

        [Test]
        public void TestParseEmpty()
        {
            String toParse = "# Generated by iptables-save v1.4.14 on Thu Jan 23 09:35:00 2014\n*nat\n:PREROUTING ACCEPT [86679:5237632]\n:INPUT ACCEPT [86679:5237632]\n:OUTPUT ACCEPT [14399:1088627]\n:POSTROUTING ACCEPT [14399:1088627]\nCOMMIT\n# Completed on Thu Jan 23 09:35:00 2014\n# Generated by iptables-save v1.4.14 on Thu Jan 23 09:35:00 2014\n*mangle\n:PREROUTING ACCEPT [56021536:11338169874]\n:INPUT ACCEPT [56021536:11338169874]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [55728201:15310624961]\n:POSTROUTING ACCEPT [55728201:15310624961]\nCOMMIT\n# Completed on Thu Jan 23 09:35:00 2014\n# Generated by iptables-save v1.4.14 on Thu Jan 23 09:35:00 2014\n*filter\n:INPUT ACCEPT [56023324:11339256702]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [55729567:15310937004]\nCOMMIT\n# Completed on Thu Jan 23 09:35:00 2014";

            var rules = Processor.GetRulesFromOutput(toParse, "filter");

            Assert.AreEqual(3, rules.Count);
            Assert.AreEqual(0, rules.ElementAt(0).Value.Count);
            Assert.AreEqual(0, rules.ElementAt(1).Value.Count);
            Assert.AreEqual(0, rules.ElementAt(2).Value.Count);
        }

        [Test]
        public void TestParseBlocklist()
        {
            String toParse = "# Generated by iptables-save v2.2.8 on Thu Jan 23 22:02:22 2022\n*mangle\n:PREROUTING ACCEPT [999766065:220658905322]\n:INPUT ACCEPT [998539822:220605322797]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [762202277:220227237260]\n:POSTROUTING ACCEPT [770922605:222320062522]\nCOMMIT\n# Completed on Thu Jan 23 22:02:22 2022\n# Generated by iptables-save v2.2.8 on Thu Jan 23 22:02:22 2022\n*nat\n:PREROUTING ACCEPT [225280362:5863766672]\n:POSTROUTING ACCEPT [32225082:2238509609]\n:OUTPUT ACCEPT [32225082:2238509609]\nCOMMIT\n# Completed on Thu Jan 23 22:02:22 2022\n# Generated by iptables-save v2.2.8 on Thu Jan 23 22:02:22 2022\n*filter\n:INPUT ACCEPT [52279:22252772]\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [27263:22000629]\n-A INPUT -s 62.32.5.230/32 -p tcp -m tcp --dport 6379 -j ACCEPT\n-A INPUT -s 298.228.83.66/32 -p tcp -m tcp --dport 6379 -j ACCEPT\n-A INPUT -s 26.27.96.227/32 -p tcp -m tcp --dport 6379 -j ACCEPT\n-A INPUT -s 5.9.292.228/32 -p tcp -m tcp --dport 6379 -j ACCEPT\n-A INPUT -s 227.0.0.2/32 -p tcp -m tcp --dport 6379 -j ACCEPT\n-A INPUT -p tcp -m tcp --dport 6379 -j DROP\n-A INPUT -s 62.32.5.230/32 -p tcp -m tcp --dport 6380 -j ACCEPT\n-A INPUT -s 286.2.265.229/32 -p tcp -m tcp --dport 6380 -j ACCEPT\n-A INPUT -s 285.8.296.273/32 -p tcp -m tcp --dport 6380 -j ACCEPT\n-A INPUT -s 227.0.0.2/32 -p tcp -m tcp --dport 6380 -j ACCEPT\n-A INPUT -p tcp -m tcp --dport 6380 -j DROP\nCOMMIT";

            var rules = Processor.GetRulesFromOutput(toParse, "filter");

            Assert.AreEqual(3, rules.Count);

        }

        [Test]
        public static void TestParsePortForward()
        {
            String toParse = "# Generated by iptables-save v1.4.8 on Thu Jan 23 12:45:54 2014\n*mangle\n:PREROUTING ACCEPT [6589433459:1321433076992]\n:INPUT ACCEPT [6585973538:1320772115659]\n:FORWARD ACCEPT [3439179:658069875]\n:OUTPUT ACCEPT [6442353697:1227342261515]\n:POSTROUTING ACCEPT [6449012996:1228367946566]\nCOMMIT\n# Completed on Thu Jan 23 12:45:54 2014\n# Generated by iptables-save v1.4.8 on Thu Jan 23 12:45:54 2014\n*nat\n:PREROUTING ACCEPT [21501161:5818875112]\n:POSTROUTING ACCEPT [969725:45869355]\n:OUTPUT ACCEPT [1005839:48941697]\n-A PREROUTING -d 103.249.10.104/32 -p tcp -m tcp --dport 6667 -m comment --comment \"auto:tunnel\" -j DNAT --to-destination 10.0.0.26:6667\n-A POSTROUTING -s 10.17.14.8/30 -m comment --comment \"auto:tunnel\" -j SNAT --to-source 103.19.70.55\nCOMMIT\n# Completed on Thu Jan 23 12:45:54 2014\n# Generated by iptables-save v1.4.8 on Thu Jan 23 12:45:54 2014\n*filter\n:INPUT ACCEPT [64124:20124977]\n:FORWARD ACCEPT [18:1426]\n:OUTPUT ACCEPT [57587:18660240]\n:fail2ban-ssh - [0:0]\n-A INPUT -p tcp -m multiport --dports 22 -j fail2ban-ssh\n-A INPUT -p tcp -m tcp --dport 6380 -j DROP\n-A INPUT -p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN -m state --state NEW -j DROP\n-A INPUT -f -j DROP\n-A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -j DROP\n-A INPUT -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP\n-A FORWARD -s 10.0.0.26/32 -m comment --comment \"auto:tunnel\"\n-A FORWARD -d 10.0.1.11/32 -p tcp -m tcp --dport 617 -m state --state NEW,RELATED,ESTABLISHED -m comment --comment \"auto:tunnel\" -j ACCEPT\n-A fail2ban-ssh -j RETURN\nCOMMIT\n# Completed on Thu Jan 23 12:45:54 2014";

            var rules = Processor.GetRulesFromOutput(toParse, "nat");
        }
    }
}
