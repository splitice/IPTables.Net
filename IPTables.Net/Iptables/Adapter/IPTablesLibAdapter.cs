using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.Adapter.Client;
using IPTables.Net.Netfilter;

namespace IPTables.Net.Iptables.Adapter
{
    public class IPTablesLibAdapter : IPTablesAdapterBase
    {
        public override IIPTablesAdapterClient GetClient(IpTablesSystem system, int ipVersion = 4)
        {
            if (ipVersion == 6)
            {
                return new IPTablesBinaryAdapterClient(ipVersion, system, "ip6tables");
            }
            return new Client.IPTablesLibAdapterClient(ipVersion, system, ipVersion == 4 ? "iptables" : "ip6tables");
        }
    }
}
