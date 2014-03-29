using System;

namespace IPTables.Net.Iptables.Adapter.Client
{
    public interface IIPTablesAdapterClient
    {
        //Transaction
        void StartTransaction();
        void EndTransactionCommit();
        void EndTransactionRollback();

        //Rules
        IpTablesChainSet ListRules(String table);
        void DeleteRule(String table, String chainName, int position);
        void DeleteRule(IpTablesRule rule);
        void InsertRule(IpTablesRule rule);
        void ReplaceRule(IpTablesRule rule);
        void AddRule(IpTablesRule rule);

        //Chains
        bool HasChain(String table, String chainName);
        void AddChain(String table, String chainName);
        void DeleteChain(string table, string chainName, bool flush = false);
    }
}
