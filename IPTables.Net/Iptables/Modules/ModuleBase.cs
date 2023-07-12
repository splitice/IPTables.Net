using Dynamitey;
using System;
using System.Collections.Generic;
using System.Diagnostics;

namespace IPTables.Net.Iptables.Modules
{
    public abstract class ModuleBase
    {
        protected ModuleBase(int version)
        {
        }

        protected internal static ModuleEntry GetModuleEntryInternal(string moduleName, Type moduleType,
            Func<IEnumerable<string>> options, ModuleEntry.ObjectActivator activator, bool preloaded = false)
        {
            var entry = new ModuleEntry()
            {
                Name = moduleName,
                Options = options(),
                Preloaded = preloaded,
                IsTarget = false,
                Activator = activator,
            };

            Debug.Assert(entry.Options != null, "Options null for " + moduleName);

            return entry;
        }

        protected internal static ModuleEntry GetTargetModuleEntryInternal(string moduleName, Type moduleType,
            Func<IEnumerable<string>> options, ModuleEntry.ObjectActivator activator, bool preloaded = false)
        {
            var entry = new ModuleEntry
            {
                Name = moduleName,
                Options = options(),
                Preloaded = preloaded,
                IsTarget = true,
                Activator = activator
            };

            Debug.Assert(entry.Options != null, "Options null for " + moduleName);

            return entry;
        }

        public virtual object Clone()
        {
            return MemberwiseClone();
        }
    }
}