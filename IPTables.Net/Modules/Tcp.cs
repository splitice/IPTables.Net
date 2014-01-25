using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using IPTables.Net.DataTypes;
using IPTables.Net.Modules.Base;

namespace IPTables.Net.Modules
{
    class Tcp : ModuleBase, IIptablesModule
    {
        private const String OptionSourcePortLong = "--source-port";
        private const String OptionSourcePortShort = "--sport";
        private const String OptionDestinationPortLong = "--destination-port";
        private const String OptionDestinationPortShort = "--dport";
        private const String OptionDestinationTcpFlags = "--tcp-flags";
        private const String OptionSyn = "--syn";
        private const String OptionTcpOption = "--tcp-option";

        public ValueOrNot<PortOrRange> SourcePort = new ValueOrNot<PortOrRange>();
        public ValueOrNot<PortOrRange> DestinationPort = new ValueOrNot<PortOrRange>();
        public TcpFlagMatch TcpFlags = null;
        //--syn
        public ValueOrNot<int> TcpOption = new ValueOrNot<int>();

        public int Feed(RuleParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionSourcePortLong:
                case OptionSourcePortShort:
                    SourcePort.Set(not, PortOrRange.Parse(parser.GetNextArg()));
                    return 1;

                case OptionDestinationPortLong:
                case OptionDestinationPortShort:
                    DestinationPort.Set(not, PortOrRange.Parse(parser.GetNextArg()));
                    return 1;

                case OptionDestinationTcpFlags:
                    TcpFlags = TcpFlagMatch.Parse(parser.GetNextArg());
                    return 1;

                case OptionSyn:
                    if (not)
                    {
                        TcpFlags = TcpFlagMatch.NotSyn;
                    }
                    else
                    {
                        TcpFlags = TcpFlagMatch.Syn;
                    }
                    return 0;

                case OptionTcpOption:
                    TcpOption.Set(not, int.Parse(parser.GetNextArg()));
                    return 1;
            }

            return 0;
        }

        public String GetRuleString()
        {
            StringBuilder sb = new StringBuilder();

            if (!SourcePort.Null)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(SourcePort.ToOption(OptionSourcePortShort));
            }

            if (!DestinationPort.Null)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(DestinationPort.ToOption(OptionDestinationPortShort));
            }

            if (TcpFlags != null)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(OptionDestinationTcpFlags);
                sb.Append(" ");
                sb.Append(TcpFlags);
            }

            if (!TcpOption.Null)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(TcpOption.ToOption(OptionTcpOption));
            }

            return sb.ToString();
        }

        public static IEnumerable<String> GetOptions()
        {
            var options = new List<string>
                          {
                              OptionSourcePortLong,
                              OptionSourcePortShort,
                              OptionDestinationPortShort,
                              OptionDestinationPortLong,
                              OptionDestinationTcpFlags,
                              OptionSyn,
                              OptionTcpOption
                          };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("tcp", typeof (Tcp), GetOptions);
        }
    }
}
