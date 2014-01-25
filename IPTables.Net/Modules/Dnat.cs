using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using IPTables.Net.DataTypes;
using IPTables.Net.Modules.Base;

namespace IPTables.Net.Modules
{
    class Dnat : ModuleBase, IIptablesModule
    {
        private const String OptionToDestination = "--to-destination";
        private const String OptionRandom = "--random";
        private const String OptionPersisent = "--persistent";

        public String CommentText;

        public int Feed(RuleParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionToDestination:
                    CommentText = Helpers.EscapeArguments(parser.GetNextArg());
                    return 1;
            }

            return 0;
        }

        public String GetRuleString()
        {
            StringBuilder sb = new StringBuilder();

            if (CommentText != null)
            {
                sb.Append("--comment ");
                sb.Append(CommentText);
            }

            return sb.ToString();
        }

        public static IEnumerable<String> GetOptions()
        {
            var options = new List<string>
                          {
                              OptionToDestination
                          };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("dnat", typeof(Dnat), GetOptions, true);
        }
    }
}
