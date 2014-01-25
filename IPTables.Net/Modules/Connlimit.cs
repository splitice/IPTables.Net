using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using IPTables.Net.DataTypes;
using IPTables.Net.Modules.Base;

namespace IPTables.Net.Modules
{
    class Connlimit : ModuleBase, IIptablesModule
    {
        private const String OptionUpto = "--connlimit-upto";
        private const String OptionAbove = "--connlimit-above";
        private const String OptionMask = "--connlimit-mask";
        private const String OptionSourceAddr = "--connlimit-saddr";
        private const String OptionDestinationAddr = "--connlimit-daddr";

        public int Upto = -1;
        public int Above = -1;
        public int Mask = -1;

        internal enum AddrMode
        {
            Source,
            Target
        }

        public AddrMode LimitMatch = AddrMode.Source;

        public int Feed(RuleParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionUpto:
                    Upto = int.Parse(parser.GetNextArg());
                    return 1;

                case OptionAbove:
                    Above = int.Parse(parser.GetNextArg());
                    return 1;
                case OptionMask:
                    Mask = int.Parse(parser.GetNextArg());
                    return 1;

                case OptionSourceAddr:
                    LimitMatch = AddrMode.Source;
                    return 0;

                case OptionDestinationAddr:
                    LimitMatch = AddrMode.Target;
                    return 0;
            }

            return 0;
        }

        public String GetRuleString()
        {
            StringBuilder sb = new StringBuilder();

            if (Upto != -1)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append("--connlimit-upto ");
                sb.Append(Upto);
            }

            if (Above != -1)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append("--connlimit-above ");
                sb.Append(Above);
            }

            if (Mask != -1)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append("--connlimit-mask ");
                sb.Append(Mask);
            }

            if (LimitMatch != AddrMode.Source)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(OptionDestinationAddr);
            }

            return sb.ToString();
        }

        public static IEnumerable<String> GetOptions()
        {
            var options = new List<string>
                          {
                                OptionUpto,
                                OptionAbove,
                                OptionMask,
                                OptionSourceAddr,
                                OptionDestinationAddr
                          };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("connlimit", typeof(Connlimit), GetOptions);
        }
    }
}
