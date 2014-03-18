using System;
using System.Collections.Generic;

namespace IPTables.Net.Iptables.Modules
{
    public struct ModuleEntry
    {
        public bool IsTarget;
        public Type Module;
        public String Name;
        public IEnumerable<String> Options;
        public bool Polyfill;
        public bool Preloaded;
    }
}