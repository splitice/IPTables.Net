﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
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

        public IPPortOrRange ToDestination = new IPPortOrRange(IPAddress.Any);
        public bool Random = false;
        public bool Persistent = false;

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
            StringBuilder sb = new StringBuilder();

            if (Equals(ToDestination.LowerAddress, IPAddress.Any))
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(OptionToDestination+" ");
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
            return GetModuleEntryInternal("dnat", typeof(Dnat), GetOptions, true);
        }
    }
}