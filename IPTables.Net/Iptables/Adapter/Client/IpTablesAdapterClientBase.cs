using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using IPTables.Net.Exceptions;
using IPTables.Net.Netfilter;
using log4net;

namespace IPTables.Net.Iptables.Adapter.Client
{
    abstract class IpTablesAdapterClientBase : INetfilterAdapterClient
    {
        protected static readonly ILog Log = LogManager.GetLogger(typeof(INetfilterAdapterClient));

        public abstract void StartTransaction();

        public abstract void EndTransactionCommit();

        public abstract void EndTransactionRollback();

        public abstract bool HasChain(string table, string chainName);

        public abstract void AddChain(string table, string chainName);

        public abstract void DeleteChain(string table, string chainName, bool flush = false);

        public abstract void DeleteRule(String table, String chainName, int position);

        public abstract void DeleteRule(IpTablesRule rule);

        public abstract void InsertRule(IpTablesRule rule);

        public abstract void ReplaceRule(IpTablesRule rule);

        public abstract void AddRule(IpTablesRule rule);

        public abstract IpTablesChainSet ListRules(String table);

        private IpTablesRule CastRule(INetfilterRule rule)
        {
            IpTablesRule castRule = rule as IpTablesRule;

            if(castRule == null)
                throw new IpTablesNetException("Invalid rule type, not iptables");

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

        public virtual List<string> GetChains(String table)
        {
            return ListRules(table).Chains.Select((a)=>a.Name).ToList();
        }

        public abstract void Dispose();

        private static Regex MatchTable = new Regex("-t ([^\\s]+)");

        protected String ExtractTable(String rule)
        {
            var m = MatchTable.Match(rule);
            if (m.Success) return m.Groups[1].Value;
            return "filter";
        }
    }
}
