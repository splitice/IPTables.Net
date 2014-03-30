using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.NfTables
{
    class NfTablesChain
    {
        private String _name;
        private NfTablesTable _table;
        private NfNetfilterHook _hook = null;
        private List<NfTablesDataStructure> _dataStructures = new List<NfTablesDataStructure>();
        private List<NfTablesRule> _rules = new List<NfTablesRule>();
    }
}
