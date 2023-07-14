using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Multiport
{
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors | DynamicallyAccessedMemberTypes.PublicMethods | DynamicallyAccessedMemberTypes.PublicProperties | DynamicallyAccessedMemberTypes.NonPublicFields)]
    public class MultiportModule : ModuleBase, IIpTablesModule, IEquatable<MultiportModule>
    {
        private const string OptionPorts = "--ports";
        private const string OptionDestinationPorts = "--dports";
        private const string OptionSourcePorts = "--sports";
        private const string OptionDestinationPortsLong = "--destination-ports";
        private const string OptionSourcePortsLong = "--source-ports";

        public ValueOrNot<IEnumerable<PortOrRange>> DestinationPorts = new ValueOrNot<IEnumerable<PortOrRange>>();
        public ValueOrNot<IEnumerable<PortOrRange>> Ports = new ValueOrNot<IEnumerable<PortOrRange>>();
        public ValueOrNot<IEnumerable<PortOrRange>> SourcePorts = new ValueOrNot<IEnumerable<PortOrRange>>();

        public MultiportModule(int version) : base(version)
        {
        }

        public bool Equals(MultiportModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;

            if (Ports.Null != other.Ports.Null ||
                SourcePorts.Null != other.SourcePorts.Null ||
                DestinationPorts.Null != other.DestinationPorts.Null)
                return false;

            //Not's all equal
            if (Ports.Not != other.Ports.Not || DestinationPorts.Not != other.DestinationPorts.Not ||
                SourcePorts.Not != other.SourcePorts.Not)
                return false;

            if (!Ports.Null)
            {
                var ports = new HashSet<PortOrRange>(Ports.Value);
                if (!ports.SetEquals(other.Ports.Value)) return false;
            }

            if (!SourcePorts.Null)
            {
                var ports = new HashSet<PortOrRange>(SourcePorts.Value);
                if (!ports.SetEquals(other.SourcePorts.Value)) return false;
            }

            if (!DestinationPorts.Null)
            {
                var ports = new HashSet<PortOrRange>(DestinationPorts.Value);
                if (!ports.SetEquals(other.DestinationPorts.Value)) return false;
            }

            return true;
        }

        public bool NeedsLoading => true;

        public int Feed(CommandParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionPorts:
                    Ports = new ValueOrNot<IEnumerable<PortOrRange>>(ParseListOfPortOrRanges(parser.GetNextArg()), not);
                    return 1;
                case OptionDestinationPorts:
                case OptionDestinationPortsLong:
                    DestinationPorts = new ValueOrNot<IEnumerable<PortOrRange>>(
                        ParseListOfPortOrRanges(parser.GetNextArg()), not);
                    return 1;
                case OptionSourcePorts:
                case OptionSourcePortsLong:
                    SourcePorts =
                        new ValueOrNot<IEnumerable<PortOrRange>>(ParseListOfPortOrRanges(parser.GetNextArg()), not);
                    return 1;
            }

            return 0;
        }

        public string GetRuleString()
        {
            var sb = new StringBuilder();

            if (!Ports.Null && Ports.Value.Count() != 0)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                if (Ports.Not)
                    sb.Append("! ");
                sb.Append(OptionPorts + " ");
                sb.Append(string.Join(",", Ports.Value.Select(a => a.ToString()).ToArray()));
            }

            if (!DestinationPorts.Null && DestinationPorts.Value.Count() != 0)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                if (DestinationPorts.Not)
                    sb.Append("! ");
                sb.Append(OptionDestinationPorts + " ");
                sb.Append(string.Join(",", DestinationPorts.Value.Select(a => a.ToString()).ToArray()));
            }

            if (!SourcePorts.Null && SourcePorts.Value.Count() != 0)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                if (SourcePorts.Not)
                    sb.Append("! ");
                sb.Append(OptionSourcePorts + " ");
                sb.Append(string.Join(",", SourcePorts.Value.Select(a => a.ToString()).ToArray()));
            }

            return sb.ToString();
        }

        private HashSet<PortOrRange> ParseListOfPortOrRanges(string csv)
        {
            var ret = new HashSet<PortOrRange>();
            foreach (var a in csv.Split(new[] {','})) ret.Add(PortOrRange.Parse(a, ':'));
            return ret;
        }

        public static HashSet<string> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionDestinationPorts,
                OptionDestinationPortsLong,
                OptionPorts,
                OptionSourcePorts,
                OptionSourcePortsLong
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("multiport", typeof(MultiportModule), GetOptions, (version) => new MultiportModule(version));
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((MultiportModule) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = Ports.GetHashCode();
                hashCode = (hashCode * 397) ^ DestinationPorts.GetHashCode();
                hashCode = (hashCode * 397) ^ SourcePorts.GetHashCode();
                return hashCode;
            }
        }
    }
}