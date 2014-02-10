using System;
using System.Collections.Generic;

namespace IPTables.Net.Iptables.Modules
{
    public struct ModuleEntry
    {
        public Type Module;
        public String Name;
        public bool IsTarget;
        public IEnumerable<String> Options;
        public bool Preloaded;
    }
}