using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Netfilter
{
    public interface INetfilterAdapter
    {
        INetfilterAdapterClient GetClient(NetfilterSystem system);
    }
}
