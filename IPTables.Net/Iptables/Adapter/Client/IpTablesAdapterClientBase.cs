using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using IPTables.Net.Exceptions;
using Serilog;

namespace IPTables.Net.Iptables.Adapter.Client
{
    internal abstract class IpTablesAdapterClientBase : IIPTablesAdapterClient
    {
        protected static readonly ILogger Log = IPTablesLogManager.GetLogger<IIPTablesAdapterClient>();

        public abstract void StartTransaction();

        public abstract void EndTransactionCommit();

        public abstract void EndTransactionRollback();

        public abstract bool HasChain(string table, string chainName);

        public abstract void AddChain(string table, string chainName);

        public abstract void DeleteChain(string table, string chainName, bool flush = false);

        public abstract void DeleteRule(string table, string chainName, int position);

        public abstract void DeleteRule(IpTablesRule rule);

        public abstract void InsertRule(IpTablesRule rule);

        public abstract void ReplaceRule(IpTablesRule rule);

        public abstract void AddRule(IpTablesRule rule);
        public abstract void AddRule(string rule);
        public abstract Version GetIptablesVersion();

        public abstract IpTablesChainSet ListRules(string table);


        public virtual List<string> GetChains(string table)
        {
            return ListRules(table).Chains.Select((a) => a.Name).ToList();
        }

        public abstract void Dispose();

        private static Regex MatchTable = new Regex("-t ([^\\s]+)");

        protected string ExtractTable(string rule)
        {
            var m = MatchTable.Match(rule);
            if (m.Success) return m.Groups[1].Value;
            return "filter";
        }
    }
}