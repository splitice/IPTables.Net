using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Udp
{
    public class UdpModule : ModuleBase, IIpTablesModuleGod, IEquatable<UdpModule>
    {
        private const String OptionSourcePortLong = "--source-port";
        private const String OptionSourcePortShort = "--sport";
        private const String OptionDestinationPortLong = "--destination-port";
        private const String OptionDestinationPortShort = "--dport";

        public ValueOrNot<PortOrRange> DestinationPort = new ValueOrNot<PortOrRange>();
        public ValueOrNot<PortOrRange> SourcePort = new ValueOrNot<PortOrRange>();

        public bool Equals(UdpModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Equals(DestinationPort, other.DestinationPort) && Equals(SourcePort, other.SourcePort);
        }

        public bool NeedsLoading
        {
            get { return true; }
        }

        int IIpTablesModuleInternal.Feed(RuleParser parser, bool not)
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

            return sb.ToString();
        }

        public static IEnumerable<String> GetOptions()
        {
            var options = new List<string>
            {
                OptionSourcePortLong,
                OptionSourcePortShort,
                OptionDestinationPortShort,
                OptionDestinationPortLong
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("udp", typeof (UdpModule), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((UdpModule) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = (DestinationPort != null ? DestinationPort.GetHashCode() : 0);
                hashCode = (hashCode*397) ^ (SourcePort != null ? SourcePort.GetHashCode() : 0);
                return hashCode;
            }
        }
    }
}