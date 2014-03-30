using System;
using System.Collections.Generic;
using System.Linq;

namespace IPTables.Net.Iptables
{
    public class IpTablesChain
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

        internal NetfilterSystem System
        {
            get { return _system; }
        }

        public void Sync(IEnumerable<IpTablesRule> with,
            Func<IpTablesRule, IpTablesRule, bool> ruleComparerForUpdate = null,
            Func<IpTablesRule, bool> shouldDelete = null)
        {
            _system.Adapter.StartTransaction();

            SyncInternal(with, ruleComparerForUpdate, shouldDelete);

            _system.Adapter.EndTransactionCommit();
        }

        public void Delete(bool flush = false)
        {
            _system.DeleteChain(_name, _table, flush);
        }

        internal void SyncInternal(IEnumerable<IpTablesRule> with,
            Func<IpTablesRule, IpTablesRule, bool> ruleComparerForUpdate = null,
            Func<IpTablesRule, bool> shouldDelete = null)
        {
            if (ruleComparerForUpdate == null)
            {
                ruleComparerForUpdate = (a, b) => false;
            }
            if (shouldDelete == null)
            {
                shouldDelete = a => true;
            }
            List<IpTablesRule> currentRules = Rules.ToList();

            int i = 0, len = with.Count();
            foreach (IpTablesRule cR in currentRules)
            {
                //Delete any extra rules
                if (i == len)
                {
                    cR.Delete();
                    continue;
                }

                //Get the rule for comparison
                IpTablesRule withRule = with.ElementAt(i);

                if (cR.Equals(withRule))
                {
                    //No need to make any changes
                    i++;
                }
                else if (ruleComparerForUpdate(cR, withRule))
                {
                    //Replace this rule
                    cR.Replace(withRule);
                    i++;
                }
                else
                {
                    if (shouldDelete(cR))
                    {
                        cR.Delete();
                    }
                }
            }

            //Get rules to be added
            IEnumerable<IpTablesRule> remaining = with.Skip(i);
            foreach (IpTablesRule rR in remaining)
            {
                rR.Add();
            }
        }
    }
}