using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Exceptions;
using IPTables.Net.Netfilter;

namespace IPTables.Net.NfTables.Adapter.Client
{
    abstract class NfTablesAdapterClientBase : INetfilterAdapterClient
    {
        public abstract void StartTransaction();

        public abstract void EndTransactionCommit();

        public abstract void EndTransactionRollback();

        public abstract bool HasChain(string table, string chainName);

        public abstract void AddChain(string table, string chainName);

        public abstract void DeleteChain(string table, string chainName, bool flush = false);

        public abstract void DeleteRule(String table, String chainName, int position);

        public abstract void DeleteRule(NfTablesRule rule);

        public abstract void InsertRule(NfTablesRule rule);

        public abstract void ReplaceRule(NfTablesRule rule);

        public abstract void AddRule(NfTablesRule rule);

        public abstract NfTablesChainSet ListRules(String table);

        private NfTablesRule CastRule(INetfilterRule rule)
        {
            NfTablesRule castRule = rule as NfTablesRule;

            if (castRule == null)
                throw new IpTablesNetException("Invalid rule type, not nftables");

            return castRule;
        }

        public void DeleteRule(INetfilterRule rule)
        {
            DeleteRule(CastRule(rule));
        }

        public void InsertRule(INetfilterRule rule)
        {
            InsertRule(CastRule(rule));
        }

        public void ReplaceRule(INetfilterRule rule)
        {
            ReplaceRule(CastRule(rule));
        }

        public void AddRule(INetfilterRule rule)
        {
            AddRule(CastRule(rule));
        }

        INetfilterChainSet INetfilterAdapterClient.ListRules(string table)
        {
            return ListRules(table);
        }
    }
}
