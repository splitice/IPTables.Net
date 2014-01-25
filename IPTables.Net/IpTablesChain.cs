using System;
using System.Collections.Generic;

namespace IPTables.Net
{
    public class IpTablesChain
    {
        private readonly String _name;
        private readonly String _table;

        public IpTablesChain(String table, String chainName)
        {
            _name = chainName;
            _table = table;
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
            return IpTablesSystem.Instance.GetRules(_table)[_name];
        }

        public void Delete(bool flush = false)
        {
            IpTablesSystem.Instance.DeleteChain(_name, _table, flush);
        }
    }
}