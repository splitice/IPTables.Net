using System;
using IPTables.Net.Netfilter;

namespace IPTables.Net.Iptables.Adapter.Client
{
    public interface IIPTablesAdapterClient : INetfilterAdapterClient
    {
        //Rules
        IpTablesChainSet ListRules(String table);
        void DeleteRule(IpTablesRule rule);
        void InsertRule(IpTablesRule rule);
        void ReplaceRule(IpTablesRule rule);
        void AddRule(IpTablesRule rule);
    }
}
