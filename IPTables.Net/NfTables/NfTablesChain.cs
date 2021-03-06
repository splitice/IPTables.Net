﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Exceptions;
using IPTables.Net.Netfilter;

namespace IPTables.Net.NfTables
{
    public class NfTablesChain: INetfilterChain
    {
        private String _name;
        private NfTablesTable _table;
        private NfNetfilterHook _hook = null;
        private List<NfTablesDataStructure> _dataStructures = new List<NfTablesDataStructure>();
        private List<NfTablesRule> _rules = new List<NfTablesRule>();
        private int _ipVersion;

        public NfTablesChain(string tableName, string chainName, NetfilterSystem netfilterSystem)
        {
            throw new NotImplementedException();
        }

        public string Name
        {
            get { return _name; }
        }

        public string Table
        {
            get { return _table.Name; }
        }

        public int IpVersion
        {
            get { return _ipVersion; }
        }

        public IEnumerable<INetfilterRule> Rules
        {
            get { return _rules.Cast<INetfilterRule>(); }
        }

        public void AddRule(NfTablesRule rule)
        {
            _rules.Add(rule);
        }

        void INetfilterChain.AddRule(INetfilterRule rule)
        {
            var ruleCast = rule as NfTablesRule;
            if(ruleCast == null)
                throw new IpTablesNetException("Rule is of the wrong type");

            AddRule(ruleCast);
        }
    }
}
