using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Iptables.Exceptions
{
    class IpTablesParserException: Exception
    {
        public IpTablesParserException(String rule, Exception previousException): base("Error parsing rule: "+rule, previousException)
        {
            
        }
    }
}
