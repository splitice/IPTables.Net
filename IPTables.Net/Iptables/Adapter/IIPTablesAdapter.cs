using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.Adapter.Client;

namespace IPTables.Net.Iptables.Adapter
{
    public interface IIPTablesAdapter
    {
        IIPTablesAdapterClient GetClient(IpTablesSystem system);
    }
}
