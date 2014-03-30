using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Netfilter;

namespace IPTables.Net.NfTables
{
    class NfTablesChain: INetfilterChain
    {
        private String _name;
        private NfTablesTable _table;
        private NfNetfilterHook _hook = null;
        private List<NfTablesDataStructure> _dataStructures = new List<NfTablesDataStructure>();
        private List<NfTablesRule> _rules = new List<NfTablesRule>();
    }
}
