using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Tcp
{
    public class TcpModule : ModuleBase, IIpTablesModule, IEquatable<TcpModule>
    {
        private const String OptionSourcePortLong = "--source-port";
        private const String OptionSourcePortShort = "--sport";
        private const String OptionDestinationPortLong = "--destination-port";
        private const String OptionDestinationPortShort = "--dport";
        private const String OptionDestinationTcpFlags = "--tcp-flags";
        private const String OptionSyn = "--syn";
        private const String OptionTcpOption = "--tcp-option";

        public ValueOrNot<PortOrRange> DestinationPort = new ValueOrNot<PortOrRange>();
        public ValueOrNot<PortOrRange> SourcePort = new ValueOrNot<PortOrRange>();
        public ValueOrNot<TcpFlagMatch> TcpFlags = null;
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

        public bool NeedsLoading
        {
            get { return true; }
        }

        public int Feed(RuleParser parser, bool not)
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
                    TcpFlags = new ValueOrNot<TcpFlagMatch>(TcpFlagMatch.Parse(parser.GetNextArg(), parser.GetNextArg(2)), not);
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

        public String GetRuleString()
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

        public static HashSet<String> GetOptions()
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
            return GetModuleEntryInternal("tcp", typeof (TcpModule), GetOptions);
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
                int hashCode = (DestinationPort != null ? DestinationPort.GetHashCode() : 0);
                hashCode = (hashCode*397) ^ (SourcePort != null ? SourcePort.GetHashCode() : 0);
                hashCode = (hashCode*397) ^ (TcpFlags != null ? TcpFlags.GetHashCode() : 0);
                hashCode = (hashCode*397) ^ (TcpOption != null ? TcpOption.GetHashCode() : 0);
                return hashCode;
            }
        }
    }
}