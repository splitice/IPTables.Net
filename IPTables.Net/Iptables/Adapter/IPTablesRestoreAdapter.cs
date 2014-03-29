using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.Adapter.Client;

namespace IPTables.Net.Iptables.Adapter
{
    public class IPTablesRestoreAdapter : IIPTablesAdapter
    {
        private readonly String _iptablesRestoreBinary;
        public IPTablesRestoreAdapter(String iptablesRestoreBinary = "iptables-restore")
        {
            _iptablesRestoreBinary = iptablesRestoreBinary;
        }
        public IIPTablesAdapterClient GetClient(IpTablesSystem system)
        {
            return new Client.IPTablesRestoreAdapterClient(system, _iptablesRestoreBinary);
        }
    }
}
