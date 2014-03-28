using System;

namespace IPTables.Net.Iptables.Adapter.Client
{
    public interface IIPTablesAdapterClient
    {
        IpTablesChainSet ListRules(String table);
        void Delete(String table, String chainName, int position);
        void Delete(IpTablesRule rule);
        void Insert(IpTablesRule rule);
        void Replace(IpTablesRule rule);
        void Add(IpTablesRule rule);
    }
}
