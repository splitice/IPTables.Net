using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using IPTables.Net.Exceptions;

namespace IPTables.Net.Iptables.Modules
{
    public class CommandParser
    {
        private readonly string[] _arguments;
        private readonly IpTablesChainSet _chains;
        private readonly ModuleRegistry _moduleRegistry = ModuleRegistry.Instance;
        private readonly Dictionary<string, ModuleEntry> _parsers;
        public int Position = 0;

        public IpTablesCommand Command;
        private ModuleEntry? _polyfill = null;
        private IpTablesCommand _ipCommand;
        private bool _onlyCommand;
        private int _version;

        public CommandParser(string[] arguments, IpTablesCommand ipCommand, IpTablesChainSet chains, int version,
            bool onlyCommand = false)
        {
            _arguments = arguments;
            _ipCommand = ipCommand;
            _parsers = new Dictionary<string, ModuleEntry>(ModuleRegistry.PreloadOptions);
            _chains = chains;
            _onlyCommand = onlyCommand;
            _version = version;
        }

        public string ChainName => _ipCommand.ChainName;

        public IpTablesChain GetChainFromSet()
        {
            return _chains.GetChainOrDefault(_ipCommand.ChainName, _ipCommand.Table);
        }

        public IpTablesChain GetNewChain(IpTablesSystem system, int ipVersion)
        {
            return new IpTablesChain(_ipCommand.Table, _ipCommand.ChainName, ipVersion, system);
        }

        public IpTablesChain CreateChain(IpTablesSystem system, int ipVersion)
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
        /// <returns>number of arguments consumed</returns>
        public int FeedToSkip(int position, bool not)
        {
            Position = position;
            var option = GetCurrentArg();

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
                        if (offset == 0) throw new Exception("Invalid offset");
                        _ipCommand.Offset = (int) offset - 1;
                        return 2;
                    }

                    _ipCommand.Offset = -1;
                }

                return 1;
            }

            if (option == "-t")
            {
                _ipCommand.Table = GetNextArg();
                return 1;
            }

            if (_onlyCommand) return 0;

            if (option == "-m")
            {
                LoadParserModule(GetNextArg());
                return 1;
            }

            if (option == "-j") LoadParserModule(GetNextArg(), true);

            //Search each module, do it verbosely from the most recently added
            ModuleEntry m;
            if (!_parsers.TryGetValue(option, out m))
            {
                if (_polyfill.HasValue)
                    m = _polyfill.Value;
                else
                    throw new IpTablesNetException("Unknown option: \"" + option + "\"");
            }

            var module = _ipCommand.Rule.GetModuleForParseInternal(m.Name, m.Activator, _version);
            return module.Feed(this, not);
        }

        private void LoadParserModule(string name, bool isTarget = false)
        {
            ModuleEntry entry;
            if (isTarget)
            {
                var entryOrNull = _moduleRegistry.GetModuleOrDefault(name, true);

                //Check if this target is loadable target
                if (!entryOrNull.HasValue)
                    return;

                entry = entryOrNull.Value;
            }
            else
            {
                entry = _moduleRegistry.GetModule(name, _version);
                if (entry.Polyfill) _polyfill = entry;
                _ipCommand.Rule.LoadModule(entry);
            }

            if (!entry.Polyfill)
                foreach (var o in entry.Options)
                    _parsers.Add(o, entry);
        }
    }
}