using System;
using System.Collections.Generic;
using System.Linq;
using IPTables.Net.Iptables.Modules;
using IPTables.Net.Iptables.Modules.Comment;
using IPTables.Net.Iptables.Modules.Connlimit;
using IPTables.Net.Iptables.Modules.Core;
using IPTables.Net.Iptables.Modules.Dnat;
using IPTables.Net.Iptables.Modules.Snat;
using IPTables.Net.Iptables.Modules.State;
using IPTables.Net.Iptables.Modules.Tcp;
using IPTables.Net.Iptables.Modules.Udp;

namespace IPTables.Net.Iptables
{
    public class ModuleFactory
    {
        public static List<Func<ModuleEntry>> AllModules = new List<Func<ModuleEntry>>
                                                           {
                                                               CoreModule.GetModuleEntry,
                                                               TcpModule.GetModuleEntry,
                                                               UdpModule.GetModuleEntry,
                                                               DnatModule.GetModuleEntry,
                                                               SnatModule.GetModuleEntry,
                                                               ConnlimitModule.GetModuleEntry,
                                                               CommentModule.GetModuleEntry,
                                                               StateModule.GetModuleEntry
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

        public ModuleEntry GetModule(String module, bool target = false)
        {
            if (!_modules.ContainsKey(module))
            {
                throw new Exception(String.Format("The factory could not find module: {0}", module));
            }
            var m = _modules[module];
            if (m.IsTarget == target)
                return m;

            throw new Exception(String.Format("The factory could not find a module of the correct type: {0}", module));
        }

        public IEnumerable<ModuleEntry> GetPreloadModules()
        {
            return _modules.Where(a => a.Value.Preloaded).Select(a => a.Value);
        }

        public ModuleEntry? GetModuleOrDefault(String module, bool target = false)
        {
            if (!_modules.ContainsKey(module))
            {
                return null;
            }
            var m = _modules[module];
            if (m.IsTarget == target)
                return m;

            return null;
        }
    }
}