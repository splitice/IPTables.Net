using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Iptables.Modules
{
    internal interface IIpTablesModuleInternal
    {
        int Feed(RuleParser parser, bool not);
    }
}
