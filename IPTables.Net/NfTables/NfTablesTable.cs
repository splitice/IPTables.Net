using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.NfTables
{
    class NfTablesTable
    {
        private String _name;
        private String _type;

        public String Name
        {
            get { return _name; }
        }

        public String Type
        {
            get { return _type; }
        }
    }
}
