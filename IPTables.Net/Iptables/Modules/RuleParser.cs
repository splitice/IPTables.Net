using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using IPTables.Net.Exceptions;
using IPTables.Net.Netfilter;

namespace IPTables.Net.Iptables.Modules
{
    public class RuleParser
    {
        private readonly string[] _arguments;
        private readonly IpTablesChainSet _chains;
        private readonly IpTablesRule _ipRule;
        private readonly ModuleRegistry _moduleRegistry = ModuleRegistry.Instance;
        private readonly List<ModuleEntry> _parsers = new List<ModuleEntry>();
        public int Position = 0;

        private String _chainName;
        private String _tableName;
        private ModuleEntry? _polyfill = null;

        public RuleParser(string[] arguments, IpTablesRule ipRule, IpTablesChainSet chains, String defaultTable)
        {
            _arguments = arguments;
            _ipRule = ipRule;
            _parsers.AddRange(_moduleRegistry.GetPreloadModules());
            _chains = chains;
            _tableName = defaultTable;
        }

        public String ChainName
        {
            get { return _chainName; }
        }

        public IpTablesChain GetChain(NetfilterSystem system)
        {
            return _chains.GetChainOrAdd(_chainName, _tableName, system);
        }

        public String GetChainName()
        {
            return _chainName;
        }

        public IpTablesChain CreateNewChain(NetfilterSystem system, int ipVersion)
        {
            return new IpTablesChain(_tableName, _chainName, ipVersion, system);
        }

        public string GetCurrentArg()
        {
            return _arguments[Position];
        }

        public string GetNextArg(int offset = 1)
        {
            return _arguments[Position + offset];
        }

        public int GetRemainingArgs()
        {
            return _arguments.Length - Position - 1;
        }

        /// <summary>
        /// Consume arguments
        /// </summary>
        /// <param name="position">Rhe position to parse</param>
        /// <param name="not"></param>
        /// <param name="version"></param>
        /// <returns>number of arguments consumed</returns>
        public int FeedToSkip(int position, bool not, int version)
        {
            Position = position;
            String option = GetCurrentArg();

            if (option == "-m")
            {
                LoadParserModule(GetNextArg());
                return 1;
            }
            if (option == "-A")
            {
                _chainName = GetNextArg();
                return 1;
            }
            if (option == "-t")
            {
                _tableName = GetNextArg();
                return 1;
            }
            if (option == "-j")
            {
                LoadParserModule(GetNextArg(), true);
            }
            foreach (ModuleEntry m in _parsers)
            {
                if (m.Options.Contains(option))
                {
                    IIpTablesModule module = _ipRule.GetModuleForParseInternal(m.Name, m.Module, version);
                    return module.Feed(this, not);
                }
            }

            if (_polyfill != null)
            {
                IIpTablesModule module = _ipRule.GetModuleForParseInternal(_polyfill.Value.Name, _polyfill.Value.Module, version);
                return module.Feed(this, not);
            }

            throw new IpTablesNetException("Unknown option: \"" + option + "\"");
        }

        private void LoadParserModule(string name, bool isTarget = false)
        {
            ModuleEntry entry;
            if (isTarget)
            {
                ModuleEntry? entryOrNull = _moduleRegistry.GetModuleOrDefault(name, true);

                //Check if this target is loadable target
                if (!entryOrNull.HasValue)
                    return;

                entry = entryOrNull.Value;
            }
            else
            {
                entry = _moduleRegistry.GetModule(name, _ipRule.Chain.IpVersion);
                if (entry.Polyfill)
                {
                    _polyfill = entry;
                }
                _ipRule.LoadModule(entry);
            }
            if (!entry.Polyfill)
            {
                _parsers.Add(entry);
            }
        }
    }
}