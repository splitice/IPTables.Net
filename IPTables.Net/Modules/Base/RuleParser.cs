using System;
using System.Collections.Generic;
using System.Linq;

namespace IPTables.Net.Modules.Base
{
    public class RuleParser
    {
        private readonly string[] _arguments;
        private readonly IpTablesRule _ipRule;
        private readonly ModuleFactory _moduleFactory = new ModuleFactory();
        private readonly List<ModuleEntry> _parsers = new List<ModuleEntry>();
        public String Chain;
        public int Position = 0;

        public RuleParser(string[] arguments, IpTablesRule ipRule)
        {
            _arguments = arguments;
            _ipRule = ipRule;
            _parsers.AddRange(_moduleFactory.GetPreloadModules());
        }

        public string GetCurrentArg()
        {
            return _arguments[Position];
        }

        public string GetNextArg(int offset = 1)
        {
            return _arguments[Position + offset];
        }

        private static bool CanFeedModule(ModuleEntry module, String option)
        {
            return module.Options.Contains(option);
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
                Chain = GetNextArg();
                return 1;
            }
            foreach (ModuleEntry m in _parsers)
            {
                if (m.Options.Contains(option))
                {
                    IIptablesModule module = _ipRule.GetModuleForParse(m.Name, m.Module);
                    return module.Feed(this, not);
                }
            }

            throw new Exception("Unknown option: " + option);
        }

        private void LoadParserModule(string getNextArg)
        {
            _parsers.Add(_moduleFactory.GetModule(getNextArg));
        }
    }
}