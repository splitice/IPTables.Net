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
            var currentRules = Rules.ToList();

            int i = 0, len = with.Count();
            foreach(var cR in currentRules)
            {
                if (i == len)
                {
                    cR.Delete(_table, _name);
                    continue;
                }
                if (cR.Equals(with.ElementAt(i)))
                {
                    i++;
                }
                else
                {
                    cR.Delete(_table, _name);
                }
            }

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