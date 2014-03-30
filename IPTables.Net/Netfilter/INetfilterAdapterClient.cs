using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Netfilter
{
    public interface INetfilterAdapterClient
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
        INetfilterChainSet ListRules(String table);
        void DeleteRule(INetfilterRule rule);
        void InsertRule(INetfilterRule rule);
        void ReplaceRule(INetfilterRule rule);
        void AddRule(INetfilterRule rule);
    }
}
