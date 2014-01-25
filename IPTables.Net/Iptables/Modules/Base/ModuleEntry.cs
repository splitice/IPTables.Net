using System;
using System.Collections.Generic;

namespace IPTables.Net.Iptables.Modules.Base
{
    public struct ModuleEntry
    {
        public Type Module;
        public String Name;
        public IEnumerable<String> Options;
        public bool Preloaded;
    }
}