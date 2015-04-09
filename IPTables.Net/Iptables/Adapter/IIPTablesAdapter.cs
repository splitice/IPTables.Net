using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.Adapter.Client;
using IPTables.Net.Netfilter;

namespace IPTables.Net.Iptables.Adapter
{
    public interface IIPTablesAdapter : INetfilterAdapter
    {
        IIPTablesAdapterClient GetClient(IpTablesSystem system, int ipVersion = 4);
    }
}
