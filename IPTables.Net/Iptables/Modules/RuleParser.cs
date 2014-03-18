using System;
using System.Collections.Generic;
using System.Linq;

namespace IPTables.Net.Iptables.Modules
{
    internal class RuleParser
    {
        private readonly string[] _arguments;
        private readonly IpTablesChainSet _chains;
        private readonly IpTablesRule _ipRule;
        private readonly ModuleFactory _moduleFactory = new ModuleFactory();
        private readonly List<ModuleEntry> _parsers = new List<ModuleEntry>();
        public int Position = 0;

        private String _chainName;
        private String _tableName;

        public RuleParser(string[] arguments, IpTablesRule ipRule, IpTablesChainSet chains, String defaultTable)
        {
            _arguments = arguments;
            _ipRule = ipRule;
            _parsers.AddRange(_moduleFactory.GetPreloadModules());
            _chains = chains;
            _tableName = defaultTable;
        }

        public IpTablesChain GetChain(IpTablesSystem system)
        {
            return _chains.GetChainOrAdd(_chainName, _tableName, system);
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

        public int FeedToSkip(int i, bool not)
        {
            Position = i;
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
                if (!m.Polyfill)
                {
                    if (m.Options.Contains(option))
                    {
                        IIpTablesModuleGod module = _ipRule.GetModuleForParseInternal(m.Name, m.Module);
                        return module.Feed(this, not);
                    }
                }
            }
            foreach (ModuleEntry m in _parsers.Reverse<ModuleEntry>())
            {
                if (m.Polyfill)
                {
                    IIpTablesModuleGod module = _ipRule.GetModuleForParseInternal(m.Name, m.Module);
                    return module.Feed(this, not);
                }
            }

            throw new Exception("Unknown option: " + option);
        }

        private void LoadParserModule(string getNextArg, bool isTarget = false)
        {
            ModuleEntry entry;
            if (isTarget)
            {
                ModuleEntry? entryOrNull = _moduleFactory.GetModuleOrDefault(getNextArg, true);

                //Check if this target is loadable target
                if (!entryOrNull.HasValue)
                    return;

                entry = entryOrNull.Value;
            }
            else
            {
                entry = _moduleFactory.GetModule(getNextArg);
            }
            _parsers.Add(entry);
        }
    }
}