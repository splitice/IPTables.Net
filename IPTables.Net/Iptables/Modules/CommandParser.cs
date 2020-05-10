using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using IPTables.Net.Exceptions;
using IPTables.Net.Netfilter;

namespace IPTables.Net.Iptables.Modules
{
    public class CommandParser
    {
        private readonly string[] _arguments;
        private readonly IpTablesChainSet _chains;
        private readonly ModuleRegistry _moduleRegistry = ModuleRegistry.Instance;
        private readonly List<ModuleEntry> _parsers;
        public int Position = 0;

        public IpTablesCommand Command;
        private ModuleEntry? _polyfill = null;
        private IpTablesCommand _ipCommand;

        public CommandParser(string[] arguments, IpTablesCommand ipCommand, IpTablesChainSet chains, String defaultTable)
        {
            _arguments = arguments;
            _ipCommand = ipCommand;
            _parsers = ModuleRegistry.PreloadDuplicateModules.ToList();
            _chains = chains;
        }

        public String ChainName
        {
            get { return _ipCommand.ChainName; }
        }

        public IpTablesChain GetChainFromSet()
        {
            return _chains.GetChainOrDefault(_ipCommand.ChainName, _ipCommand.Table);
        }

        public IpTablesChain GetNewChain(NetfilterSystem system, int ipVersion)
        {
            return new IpTablesChain(_ipCommand.Table, _ipCommand.ChainName, ipVersion, system);
        }

        public IpTablesChain CreateChain(NetfilterSystem system, int ipVersion)
        {
            var chain = GetNewChain(system, ipVersion);
            _chains.AddChain(chain);
            return chain;
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
                LoadParserModule(GetNextArg(), version);
                return 1;
            }
            if (option == "-A" || option == "-D" || option == "-R" || option == "-I")
            {
                _ipCommand.ChainName = GetNextArg();
                _ipCommand.Type = IpTablesCommand.GetCommandType(option);
                if (option == "-D" || option == "-R" || option == "-I")
                {
                    var nextArg = GetNextArg(2);
                    uint offset;
                    if (uint.TryParse(nextArg, out offset))
                    {
                        _ipCommand.Offset = (int)offset;
                        return 2;
                    }
                    else
                    {
                        _ipCommand.Offset = -1;
                    }
                }
                return 1;
            }
            if (option == "-t")
            {
                _ipCommand.Table = GetNextArg();
                return 1;
            }
            if (option == "-j")
            {
                LoadParserModule(GetNextArg(), version, true);
            }

            //All the preloaded modules are indexed here
            ModuleEntry mQuick;
            if (ModuleRegistry.PreloadOptions.TryGetValue(option, out mQuick))
            {
                IIpTablesModule module = _ipCommand.Rule.GetModuleForParseInternal(mQuick.Name, mQuick.Activator, version);
                return module.Feed(this, not);
            }

            //Search each module, do it verbosely from the most recently added
            for (int index = _parsers.Count - 1; index >= 0; index--)
            {
                ModuleEntry m = _parsers[index];
                if (m.Options.Contains(option))
                {
                    IIpTablesModule module = _ipCommand.Rule.GetModuleForParseInternal(m.Name, m.Activator, version);
                    return module.Feed(this, not);
                }
            }

            if (_polyfill != null)
            {
                IIpTablesModule module = _ipCommand.Rule.GetModuleForParseInternal(_polyfill.Value.Name, _polyfill.Value.Activator, version);
                return module.Feed(this, not);
            }

            throw new IpTablesNetException("Unknown option: \"" + option + "\"");
        }

        private void LoadParserModule(string name, int version, bool isTarget = false)
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
                entry = _moduleRegistry.GetModule(name, version);
                if (entry.Polyfill)
                {
                    _polyfill = entry;
                }
                _ipCommand.Rule.LoadModule(entry);
            }
            if (!entry.Polyfill)
            {
                _parsers.Add(entry);
            }
        }
    }
}