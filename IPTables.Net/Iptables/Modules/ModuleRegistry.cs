using System;
using System.Collections.Generic;
using System.Linq;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.Modules.Bpf;
using IPTables.Net.Iptables.Modules.Comment;
using IPTables.Net.Iptables.Modules.Connlimit;
using IPTables.Net.Iptables.Modules.Connmark;
using IPTables.Net.Iptables.Modules.Core;
using IPTables.Net.Iptables.Modules.Ct;
using IPTables.Net.Iptables.Modules.Dnat;
using IPTables.Net.Iptables.Modules.HashLimit;
using IPTables.Net.Iptables.Modules.Helper;
using IPTables.Net.Iptables.Modules.IpSet;
using IPTables.Net.Iptables.Modules.Length;
using IPTables.Net.Iptables.Modules.Limit;
using IPTables.Net.Iptables.Modules.Log;
using IPTables.Net.Iptables.Modules.Mark;
using IPTables.Net.Iptables.Modules.Multiport;
using IPTables.Net.Iptables.Modules.Nfacct;
using IPTables.Net.Iptables.Modules.Nflog;
using IPTables.Net.Iptables.Modules.Nfqueue;
using IPTables.Net.Iptables.Modules.Polyfill;
using IPTables.Net.Iptables.Modules.Recent;
using IPTables.Net.Iptables.Modules.Snat;
using IPTables.Net.Iptables.Modules.State;
using IPTables.Net.Iptables.Modules.StringMatch;
using IPTables.Net.Iptables.Modules.SynProxy;
using IPTables.Net.Iptables.Modules.Tcp;
using IPTables.Net.Iptables.Modules.TcpMss;
using IPTables.Net.Iptables.Modules.U32;
using IPTables.Net.Iptables.Modules.Udp;

namespace IPTables.Net.Iptables.Modules
{
    public class ModuleRegistry
    {
        public static List<Func<ModuleEntry>> IncludedModules = new List<Func<ModuleEntry>>
        {
            CoreModule.GetModuleEntry,
            RejectTargetModule.GetModuleEntry,
            TcpModule.GetModuleEntry,
            UdpModule.GetModuleEntry,
            HelperModule.GetModuleEntry,
            DnatModule.GetModuleEntry,
            SnatModule.GetModuleEntry,
            CtTargetModule.GetModuleEntry,
            ConnlimitModule.GetModuleEntry,
            LimitModule.GetModuleEntry,
            HashLimitModule.GetModuleEntry,
            LengthModule.GetModuleEntry,
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
            NflogModule.GetModuleEntry,
            NfqueueModule.GetModuleEntry,
            StringModule.GetModuleEntry,
            SynProxyModule.GetModuleEntry,
            IpSetModule.GetModuleEntry,
            BpfModule.GetModuleEntry,
            U32Module.GetModuleEntry
        };

        private readonly Dictionary<String, ModuleEntry> _modules = new Dictionary<string, ModuleEntry>();
        private static ModuleRegistry _instance = new ModuleRegistry();

        internal ModuleRegistry()
        {
            foreach (var mFunc in IncludedModules)
            {
                RegisterModule(mFunc());
            }
        }

        public void RegisterModule(ModuleEntry entry)
        {
            _modules.Add(entry.Name, entry);
        }

        public static ModuleRegistry Instance
        {
            get { return _instance; }
        }

        public ModuleEntry GetModule(String module, int version, bool target = false, bool polyfill = true)
        {
            if (!_modules.ContainsKey(module))
            {
                if (polyfill)
                {
                    ModuleEntry moduleEntry = PolyfillModule.GetModuleEntry();
                    moduleEntry.Name = module;
                    return moduleEntry;
                }
                throw new IpTablesNetException(String.Format("The factory could not find module: {0}", module));
            }
            ModuleEntry m = _modules[module];
            if (m.IsTarget == target)
                return m;

            throw new IpTablesNetException(String.Format("The factory could not find a module of the correct type: {0}", module));
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