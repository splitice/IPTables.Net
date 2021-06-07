using IPTables.Net.IpSet;
using IPTables.Net.IpSet.Adapter;

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

        public override IpSetSets SaveSets(IpTablesSystem iptables, string setName = null)
        {
            return _sets;
        }
    }
}
