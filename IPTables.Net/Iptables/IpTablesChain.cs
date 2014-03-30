using System;
using System.Collections.Generic;
using System.Linq;
using IPTables.Net.Netfilter;
using IPTables.Net.Netfilter.Sync;

namespace IPTables.Net.Iptables
{
    public class IpTablesChain : INetfilterChain
    {
        private readonly String _name;
        private readonly List<IpTablesRule> _rules;
        private readonly NetfilterSystem _system;
        private readonly String _table;

        public IpTablesChain(String table, String chainName, NetfilterSystem system, List<IpTablesRule> rules)
        {
            _name = chainName;
            _table = table;
            _system = system;
            _rules = rules;
        }

        public IpTablesChain(String table, String chainName, NetfilterSystem system)
        {
            _name = chainName;
            _table = table;
            _system = system;
            _rules = new List<IpTablesRule>();
        }

        public String Name
        {
            get { return _name; }
        }

        public String Table
        {
            get { return _table; }
        }

        public List<IpTablesRule> Rules
        {
            get { return _rules; }
        }

        IEnumerable<INetfilterRule> INetfilterChain.Rules
        {
            get { return _rules.Cast<INetfilterRule>(); }
        } 

        internal NetfilterSystem System
        {
            get { return _system; }
        }

        public void Sync(IEnumerable<IpTablesRule> with,
            INetfilterSync<IpTablesRule> sync)
        {
            _system.Adapter.StartTransaction();

            SyncInternal(with, sync);

            _system.Adapter.EndTransactionCommit();
        }

        public void Delete(bool flush = false)
        {
            _system.DeleteChain(_name, _table, flush);
        }

        internal void SyncInternal(IEnumerable<IpTablesRule> with,
            INetfilterSync<IpTablesRule> sync)
        {
            sync.SyncChainRules(with, Rules);
        }
    }
}