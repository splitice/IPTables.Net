using System;
using System.Collections.Generic;
using System.Linq;
using System.Linq.Expressions;
using System.Reflection;

namespace IPTables.Net.Iptables.Modules
{
    public struct ModuleEntry
    {
        public bool IsTarget;
        
        public string Name;
        public IEnumerable<string> Options;
        public bool Polyfill;
        public bool Preloaded;
        public bool Duplicated;
        public ObjectActivator Activator;

        public delegate IIpTablesModule ObjectActivator(int version);
    }
}