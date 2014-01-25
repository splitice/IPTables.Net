using System;
using System.Collections.Generic;

namespace IPTables.Net.Modules.Base
{
    abstract class ModuleBase
    {
        protected static ModuleEntry GetModuleEntryInternal(String moduleName, Type moduleType, Func<IEnumerable<String>> options)
        {
            ModuleEntry entry = new ModuleEntry();
            entry.Name = moduleName;
            entry.Module = moduleType;
            entry.Options = options();
            return entry;
        }
    }
}
