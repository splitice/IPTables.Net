using System;
using System.Collections.Generic;

namespace IPTables.Net.Modules.Base
{
    public struct ModuleEntry
    {
        public String Name;
        public Type Module;
        public IEnumerable<String> Options;
    }
}
