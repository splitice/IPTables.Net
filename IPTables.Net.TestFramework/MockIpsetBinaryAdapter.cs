using IPTables.Net.Iptables.IpSet;
using IPTables.Net.Iptables.IpSet.Adapter;

namespace IPTables.Net.TestFramework
{
    public class MockIpsetBinaryAdapter: IpSetBinaryAdapter
    {
        private IpSetSets _sets;

        public MockIpsetBinaryAdapter(MockIpsetSystemFactory systemFactory, IpSetSets sets = null)
            : base(systemFactory)
        {
            SetSets(sets);
        }

        public void SetSets(IpSetSets sets)
        {
            _sets = sets;
        }

        public override IpSetSets SaveSets(IpTablesSystem iptables)
        {
            return _sets;
        }
    }
}
