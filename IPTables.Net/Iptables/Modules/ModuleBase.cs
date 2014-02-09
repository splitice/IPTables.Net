using System;
using System.Collections.Generic;

namespace IPTables.Net.Iptables.Modules.Base
{
    public abstract class ModuleBase
    {
        protected internal static ModuleEntry GetModuleEntryInternal(String moduleName, Type moduleType,
            Func<IEnumerable<String>> options, bool preloaded = false)
        {
            var entry = new ModuleEntry
                        {
                            Name = moduleName,
                            Module = moduleType,
                            Options = options(),
                            Preloaded = preloaded
                        };
            return entry;
        }
    }
}