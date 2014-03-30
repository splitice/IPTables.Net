using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Netfilter;

namespace IPTables.Net.NfTables
{
    class NfTablesRule: INetfilterRule
    {
        private NfTablesTable _table;
        private String _chain;

        public void Delete(bool usingPosition = true)
        {
            throw new NotImplementedException();
        }

        public void Add()
        {
            throw new NotImplementedException();
        }

        public void Replace(INetfilterRule with)
        {
            throw new NotImplementedException();
        }
    }
}
