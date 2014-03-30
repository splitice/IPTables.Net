using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.NfTables.Adapter
{
    class NfTablesBinaryAdapter
    {
        private String _binary;

        public NfTablesBinaryAdapter(String binary = "nft")
        {
            _binary = binary;
        }
    }
}
