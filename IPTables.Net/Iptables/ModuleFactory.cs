using System;
using System.Collections.Generic;
using System.Linq;
using IPTables.Net.Iptables.Modules;
using IPTables.Net.Iptables.Modules.Base;

namespace IPTables.Net.Iptables
{
    public class ModuleFactory
    {
        public static List<Func<ModuleEntry>> AllModules = new List<Func<ModuleEntry>>
                                                           {
                                                               Core.GetModuleEntry,
                                                               Tcp.GetModuleEntry,
                                                               Dnat.GetModuleEntry,
                                                               Snat.GetModuleEntry,
                                                               Connlimit.GetModuleEntry,
                                                               Comment.GetModuleEntry
                                                           };

        private readonly Dictionary<String, ModuleEntry> _modules = new Dictionary<string, ModuleEntry>();

        public ModuleFactory()
        {
            foreach (var mFunc in AllModules)
            {
                ModuleEntry m = mFunc();

                _modules.Add(m.Name, m);
            }
        }

        public ModuleEntry GetModule(String module)
        {
            return _modules[module];
        }

        public IEnumerable<ModuleEntry> GetPreloadModules()
        {
            return _modules.Where(a => a.Value.Preloaded).Select(a => a.Value);
        }
    }
}