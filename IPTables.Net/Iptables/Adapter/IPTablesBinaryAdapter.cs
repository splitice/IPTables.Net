using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.Adapter.Client;

namespace IPTables.Net.Iptables.Adapter
{
    public class IPTablesBinaryAdapter : IIPTablesAdapter
    {
        public IIPTablesAdapterClient GetClient(IpTablesSystem system)
        {
            return new Client.IPTablesBinaryAdapterClient(system);
        }
    }
}
