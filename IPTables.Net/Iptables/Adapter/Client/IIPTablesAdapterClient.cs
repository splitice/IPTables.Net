using System;
using System.Collections.Generic;
using IPTables.Net.Netfilter;

namespace IPTables.Net.Iptables.Adapter.Client
{
    public interface IIPTablesAdapterClient : IDisposable
    {
        //Transaction
        void StartTransaction();
        void EndTransactionCommit();
        void EndTransactionRollback();

        //Chains
        bool HasChain(String table, String chainName);
        void AddChain(String table, String chainName);
        void DeleteChain(string table, string chainName, bool flush = false);

        //Rules
        void DeleteRule(String table, String chainName, int position);
        new IpTablesChainSet ListRules(String table);


        void DeleteRule(IpTablesRule rule);
        void InsertRule(IpTablesRule rule);
        void ReplaceRule(IpTablesRule rule);
        void AddRule(IpTablesRule rule);
        void AddRule(String rule);
        Version GetIptablesVersion();
        List<String> GetChains(String table);
    }
}
