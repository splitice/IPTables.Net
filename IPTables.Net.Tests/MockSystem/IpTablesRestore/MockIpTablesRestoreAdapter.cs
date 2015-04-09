using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.Adapter;
using IPTables.Net.Iptables.Adapter.Client;
using IPTables.Net.Netfilter;

namespace IPTables.Net.Tests.MockSystem.IpTablesRestore
{
    class MockIpTablesRestoreAdapter: IPTablesAdapterBase
    {
        public override IIPTablesAdapterClient GetClient(IpTablesSystem system, int ipVersion = 4)
        {
            return new MockIpTablesRestoreAdapterClient(system);
        }
    }
}
