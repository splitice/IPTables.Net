using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.Adapter.Client;

namespace IPTables.Net.Iptables.Adapter
{
    public class IPTablesLibAdapter : IPTablesAdapterBase
    {
        public override IIPTablesAdapterClient GetClient(IpTablesSystem system, int ipVersion = 4)
        {
            return new IPTablesLibAdapterClient(ipVersion, system, ipVersion == 4 ? "iptables" : "ip6tables");
        }
    }
}