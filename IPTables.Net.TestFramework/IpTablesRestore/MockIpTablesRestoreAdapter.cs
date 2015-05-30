using IPTables.Net.Iptables.Adapter;
using IPTables.Net.Iptables.Adapter.Client;

namespace IPTables.Net.TestFramework.IpTablesRestore
{
    public class MockIpTablesRestoreAdapter: IPTablesAdapterBase
    {
        public override IIPTablesAdapterClient GetClient(IpTablesSystem system, int ipVersion = 4)
        {
            return new MockIpTablesRestoreAdapterClient(system);
        }
    }
}
