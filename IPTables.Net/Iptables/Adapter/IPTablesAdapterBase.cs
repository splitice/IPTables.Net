using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.Adapter.Client;
using IPTables.Net.Netfilter;

namespace IPTables.Net.Iptables.Adapter
{
    public abstract class IPTablesAdapterBase : IIPTablesAdapter
    {
        public abstract IIPTablesAdapterClient GetClient(IpTablesSystem system, int ipVersion = 4);
    }
}