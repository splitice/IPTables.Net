using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using IPTables.Net.DataTypes;
using IPTables.Net.Modules.Base;

namespace IPTables.Net.Modules
{
    internal class Dnat : ModuleBase, IIptablesModule
    {
        private const String OptionToDestination = "--to-destination";
        private const String OptionRandom = "--random";
        private const String OptionPersisent = "--persistent";

        public bool Persistent = false;
        public bool Random = false;
        public IPPortOrRange ToDestination = new IPPortOrRange(IPAddress.Any);

        public int Feed(RuleParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionToDestination:
                    ToDestination = IPPortOrRange.Parse(parser.GetNextArg());
                    return 1;

                case OptionRandom:
                    Random = true;
                    return 0;

                case OptionPersisent:
                    Persistent = true;
                    return 0;
            }

            return 0;
        }

        public String GetRuleString()
        {
            var sb = new StringBuilder();

            if (Equals(ToDestination.LowerAddress, IPAddress.Any))
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(OptionToDestination + " ");
                sb.Append(ToDestination);
            }

            if (Random)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(OptionRandom);
            }

            if (Persistent)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(OptionPersisent);
            }

            return sb.ToString();
        }

        public static IEnumerable<String> GetOptions()
        {
            var options = new List<string>
                          {
                              OptionToDestination,
                              OptionRandom,
                              OptionPersisent
                          };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("dnat", typeof (Dnat), GetOptions, true);
        }
    }
}