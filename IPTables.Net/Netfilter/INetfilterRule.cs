using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Netfilter
{
    public interface INetfilterRule
    {
        void Delete(bool usingPosition = true);
        void Add();
        void Replace(INetfilterRule with);
    }
}
