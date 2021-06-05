using System;
using System.Collections.Generic;

namespace IPTables.Net.Iptables.Adapter.Client
{
    public interface IIPTablesAdapterClient : IDisposable
    {
        //Transaction
        void StartTransaction();
        void EndTransactionCommit();
        void EndTransactionRollback();

        //Chains
        bool HasChain(string table, string chainName);
        void AddChain(string table, string chainName);
        void DeleteChain(string table, string chainName, bool flush = false);

        //Rules
        void DeleteRule(string table, string chainName, int position);
        new IpTablesChainSet ListRules(string table);


        void DeleteRule(IpTablesRule rule);
        void InsertRule(IpTablesRule rule);
        void ReplaceRule(IpTablesRule rule);
        void AddRule(IpTablesRule rule);
        void AddRule(string rule);
        Version GetIptablesVersion();
        List<string> GetChains(string table);
    }
}