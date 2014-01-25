using System;
using System.Collections.Generic;

namespace IPTables.Net.Modules.Base
{
    abstract class ModuleBase
    {
        protected static ModuleEntry GetModuleEntryInternal(String moduleName, Type moduleType, Func<IEnumerable<String>> options, bool preloaded = false)
        {
            ModuleEntry entry = new ModuleEntry
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
