using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Tcp
{
    public class TcpModule : ModuleBase, IIpTablesModule, IEquatable<TcpModule>
    {
        private const string OptionSourcePortLong = "--source-port";
        private const string OptionSourcePortShort = "--sport";
        private const string OptionDestinationPortLong = "--destination-port";
        private const string OptionDestinationPortShort = "--dport";
        private const string OptionDestinationTcpFlags = "--tcp-flags";
        private const string OptionSyn = "--syn";
        private const string OptionTcpOption = "--tcp-option";

        public ValueOrNot<PortOrRange> DestinationPort = new ValueOrNot<PortOrRange>();
        public ValueOrNot<PortOrRange> SourcePort = new ValueOrNot<PortOrRange>();

        public ValueOrNot<TcpFlagMatch> TcpFlags = new ValueOrNot<TcpFlagMatch>();

        //--syn
        public ValueOrNot<int> TcpOption = new ValueOrNot<int>();

        public TcpModule(int version) : base(version)
        {
        }

        public bool Equals(TcpModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Equals(DestinationPort, other.DestinationPort) && Equals(SourcePort, other.SourcePort) &&
                   Equals(TcpFlags, other.TcpFlags) && Equals(TcpOption, other.TcpOption);
        }

        public bool NeedsLoading => true;

        public int Feed(CommandParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionSourcePortLong:
                case OptionSourcePortShort:
                    SourcePort.Set(not, PortOrRange.Parse(parser.GetNextArg(), ':'));
                    return 1;

                case OptionDestinationPortLong:
                case OptionDestinationPortShort:
                    DestinationPort.Set(not, PortOrRange.Parse(parser.GetNextArg(), ':'));
                    return 1;

                case OptionDestinationTcpFlags:
                    TcpFlags = new ValueOrNot<TcpFlagMatch>(
                        TcpFlagMatch.Parse(parser.GetNextArg(), parser.GetNextArg(2)), not);
                    return 2;

                case OptionSyn:
                    TcpFlags = new ValueOrNot<TcpFlagMatch>(TcpFlagMatch.Syn, not);
                    return 0;

                case OptionTcpOption:
                    TcpOption.Set(not, int.Parse(parser.GetNextArg()));
                    return 1;
            }

            return 0;
        }

        public string GetRuleString()
        {
            var sb = new StringBuilder();

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

            if (!TcpFlags.Null)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(TcpFlags.ToOption(OptionDestinationTcpFlags, null, false));
            }

            if (!TcpOption.Null)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(TcpOption.ToOption(OptionTcpOption));
            }

            return sb.ToString();
        }

        public static HashSet<string> GetOptions()
        {
            var options = new HashSet<string>
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
            return GetModuleEntryInternal("tcp", typeof(TcpModule), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((TcpModule) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = DestinationPort.GetHashCode();
                hashCode = (hashCode * 397) ^ SourcePort.GetHashCode();
                hashCode = (hashCode * 397) ^ TcpFlags.GetHashCode();
                hashCode = (hashCode * 397) ^ TcpOption.GetHashCode();
                return hashCode;
            }
        }
    }
}