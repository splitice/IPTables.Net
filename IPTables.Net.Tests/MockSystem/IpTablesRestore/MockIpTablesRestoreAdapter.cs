using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.Adapter;
using IPTables.Net.Iptables.Adapter.Client;

namespace IPTables.Net.Tests.MockSystem.IpTablesRestore
{
    class MockIpTablesRestoreAdapter: IIPTablesAdapter
    {
        public IIPTablesAdapterClient GetClient(IpTablesSystem system)
        {
            return new MockIpTablesRestoreAdapterClient(system);
        }
    }
}
