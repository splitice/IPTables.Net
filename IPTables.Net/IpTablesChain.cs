using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net
{
    public class IpTablesChain
    {
        private String _name;
        private String _table;

        public String Name
        {
            get
            {
                return _name;
            }
        }

        public String Table
        {
            get
            {
                return _table;
            }
        }

        public IpTablesChain(String table, String chainName)
        {
            _name = chainName;
            _table = table;
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
