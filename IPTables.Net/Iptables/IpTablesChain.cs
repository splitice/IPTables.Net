using System;
using System.Collections.Generic;
using System.Linq;

namespace IPTables.Net.Iptables
{
    public class IpTablesChain
    {
        private readonly String _name;
        private readonly String _table;
        private IpTablesSystem _system;

        public IpTablesChain(String table, String chainName, IpTablesSystem system, List<IpTablesRule> rules)
        {
            _name = chainName;
            _table = table;
            _system = system;
            _rules = rules;
        }

        public IpTablesChain(String table, String chainName, IpTablesSystem system)
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

        private List<IpTablesRule> _rules;
        public List<IpTablesRule> Rules
        {
            get
            {
                return _rules;
            }
        }

        public void Sync(IEnumerable<IpTablesRule> with)
        {
            Sync(with, (a, b) => false);
        }

        public void Sync(IEnumerable<IpTablesRule> with, Func<IpTablesRule, IpTablesRule, bool> ruleComparerForUpdate)
        {
            var currentRules = Rules.ToList();

            int i = 0, len = with.Count();
            foreach(var cR in currentRules)
            {
                //Delete any extra rules
                if (i == len)
                {
                    cR.Delete(_table, _name);
                    continue;
                }

                //Get the rule for comparison
                var withRule = with.ElementAt(i);

                if (cR.Equals(withRule))
                {
                    //No need to make any changes
                    i++;
                }
                else if (ruleComparerForUpdate(cR, withRule))
                {
                    //Replace this rule
                    cR.Replace(_table, _name, withRule);
                    i++;
                }
                else
                {
                    cR.Delete(_table, _name);
                }
            }

            //Get rules to be added
            var remaining = with.Skip(i);
            foreach (var rR in remaining)
            {
                rR.Add(_table, _name);
            }
        }

        public void Delete(bool flush = false)
        {
            _system.DeleteChain(_name, _table, flush);
        }
    }
}