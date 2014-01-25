using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;


namespace IPTables.Net
{
    class IPTablesProcessor
    {
        private static ModuleFactory _moduleFactory = new ModuleFactory();
        private readonly IPTablesSave _adapter;

        public IPTablesProcessor()
        {
            _adapter = new IPTablesSave(_moduleFactory);
        }

        public List<IpTablesRule> GetRules(String table)
        {
            return _adapter.GetRules(table);
        }
    }
}
