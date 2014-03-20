using System;
using System.Collections.Generic;
using System.Linq;
using IPTables.Net.Iptables.Modules;
using IPTables.Net.Iptables.Modules.Comment;
using IPTables.Net.Iptables.Modules.Connlimit;
using IPTables.Net.Iptables.Modules.Connmark;
using IPTables.Net.Iptables.Modules.Core;
using IPTables.Net.Iptables.Modules.Dnat;
using IPTables.Net.Iptables.Modules.Log;
using IPTables.Net.Iptables.Modules.Mark;
using IPTables.Net.Iptables.Modules.Multiport;
using IPTables.Net.Iptables.Modules.Nfacct;
using IPTables.Net.Iptables.Modules.Polyfill;
using IPTables.Net.Iptables.Modules.Recent;
using IPTables.Net.Iptables.Modules.Snat;
using IPTables.Net.Iptables.Modules.State;
using IPTables.Net.Iptables.Modules.Tcp;
using IPTables.Net.Iptables.Modules.TcpMss;
using IPTables.Net.Iptables.Modules.Udp;

namespace IPTables.Net.Iptables
{
    public class ModuleFactory
    {
        public static List<Func<ModuleEntry>> AllModules = new List<Func<ModuleEntry>>
        {
            CoreModule.GetModuleEntry,
            RejectTargetModule.GetModuleEntry,
            TcpModule.GetModuleEntry,
            UdpModule.GetModuleEntry,
            DnatModule.GetModuleEntry,
            SnatModule.GetModuleEntry,
            ConnlimitModule.GetModuleEntry,
            CommentModule.GetModuleEntry,
            NfacctModule.GetModuleEntry,
            StateModule.GetModuleEntry,
            MarkLoadableModule.GetModuleEntry,
            MarkTargetModule.GetModuleEntry,
            ConnmarkLoadableModule.GetModuleEntry,
            ConnmarkTargetModule.GetModuleEntry,
            RecentModule.GetModuleEntry,
            TcpMssModule.GetModuleEntry,
            MultiportModule.GetModuleEntry,
            LogModule.GetModuleEntry,
            PolyfillModule.GetModuleEntry
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

        public ModuleEntry GetModule(String module, bool target = false, bool polyfill = true)
        {
            if (!_modules.ContainsKey(module))
            {
                if (polyfill)
                {
                    IEnumerable<ModuleEntry> pm = _modules.Select(a => a.Value).Where(a => a.Polyfill);
                    if (pm.Count() != 0)
                    {
                        ModuleEntry moduleEntry = pm.FirstOrDefault();
                        moduleEntry.Name = module;
                        return moduleEntry;
                    }
                }
                throw new Exception(String.Format("The factory could not find module: {0}", module));
            }
            ModuleEntry m = _modules[module];
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
            ModuleEntry m = _modules[module];
            if (m.IsTarget == target)
                return m;

            return null;
        }
    }
}