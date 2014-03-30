using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.NfTables.DataTypes;

namespace IPTables.Net.NfTables
{
    class NfTablesDataStructure
    {
        private String _name;
        private INfDataType _dataType;

        public String Name
        {
            get { return _name; }
        }

        public INfDataType Data
        {
            get { return _dataType; }
        }
    }
}
