using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Netfilter
{
    interface INetfilterChain
    {
        String Name { get; }

        String Table { get; }

        IEnumerable<INetfilterRule> Rules { get; }
    }
}
