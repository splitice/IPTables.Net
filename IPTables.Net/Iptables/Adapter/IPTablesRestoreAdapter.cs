using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.Adapter.Client;
using IPTables.Net.Netfilter;

namespace IPTables.Net.Iptables.Adapter
{
    public class IPTablesRestoreAdapter : IPTablesAdapterBase
    {
        private readonly String _iptablesRestoreBinary;
        public IPTablesRestoreAdapter(String iptablesRestoreBinary = "xtables-multi iptables-restore")
        {
            _iptablesRestoreBinary = iptablesRestoreBinary;
        }
        public override IIPTablesAdapterClient GetClient(IpTablesSystem system)
        {
            return new Client.IPTablesRestoreAdapterClient(system, _iptablesRestoreBinary);
        }
    }
}
