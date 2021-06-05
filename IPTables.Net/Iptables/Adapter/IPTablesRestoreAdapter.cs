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
        private readonly string _iptablesRestoreBinary4;
        private readonly string _iptablesSaveBinary4;
        private readonly string _iptablesRestoreBinary6;
        private readonly string _iptablesSaveBinary6;

        public IPTablesRestoreAdapter(string iptablesRestoreBinary4 = "iptables-restore",
            string iptableSaveBinary4 = "iptables-save", string iptablesRestoreBinary6 = "ip6tables-restore",
            string iptableSaveBinary6 = "ip6tables-save")
        {
            _iptablesRestoreBinary4 = iptablesRestoreBinary4;
            _iptablesSaveBinary4 = iptableSaveBinary4;
            _iptablesRestoreBinary6 = iptablesRestoreBinary6;
            _iptablesSaveBinary6 = iptableSaveBinary6;
        }

        public override IIPTablesAdapterClient GetClient(IpTablesSystem system, int ipVersion = 4)
        {
            return new IPTablesRestoreAdapterClient(ipVersion, system,
                ipVersion == 4 ? _iptablesRestoreBinary4 : _iptablesRestoreBinary6,
                ipVersion == 4 ? _iptablesSaveBinary4 : _iptablesSaveBinary6,
                ipVersion == 4 ? "iptables" : "ip6tables");
        }

        public void CheckBinary(IpTablesSystem system, int ipVersion)
        {
            using (var client = GetClient(system, ipVersion))
            {
                (client as IPTablesRestoreAdapterClient).CheckBinary();
            }
        }
    }
}