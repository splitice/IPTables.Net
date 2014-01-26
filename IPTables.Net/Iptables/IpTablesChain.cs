using System;
using System.Collections.Generic;

namespace IPTables.Net.Iptables
{
    public class IpTablesChain
    {
        private readonly String _name;
        private readonly String _table;
        private IpTablesSystem _system;

        public IpTablesChain(String table, String chainName, IpTablesSystem system)
        {
            _name = chainName;
            _table = table;
            _system = system;
        }

        public String Name
        {
            get { return _name; }
        }

        public String Table
        {
            get { return _table; }
        }

        public IEnumerable<IpTablesRule> GetRules()
        {
            return _system.GetRules(_table)[_name];
        }

        public void Delete(bool flush = false)
        {
            _system.DeleteChain(_name, _table, flush);
        }
    }
}