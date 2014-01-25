using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using IPTables.Net.Modules.Base;

namespace IPTables.Net
{
    public class ModuleFactory
    {
        public static List<Func<ModuleEntry>> AllModules = new List<Func<ModuleEntry>>()
                                                        {
                                                            Modules.Core.GetModuleEntry,
                                                            Modules.Tcp.GetModuleEntry,
                                                            Modules.Connlimit.GetModuleEntry,
                                                            Modules.Comment.GetModuleEntry
                                                        };

        private readonly Dictionary<String, ModuleEntry> _modules = new Dictionary<string, ModuleEntry>();

        public ModuleFactory()
        {
            foreach (var mFunc in AllModules)
            {
                var m = mFunc();

                _modules.Add(m.Name, m);
            }
        }

        public ModuleEntry GetModule(String module)
        {
            return _modules[module];
        }

        public IEnumerable<ModuleEntry> GetPreloadModules()
        {
            return _modules.Where((a) => a.Value.Preloaded).Select((a)=>a.Value);
        }
    }
}
