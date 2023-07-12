using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.DataTypes;
using IPTables.Net.Iptables.Helpers;
using IPTables.Net.Supporting;

namespace IPTables.Net.Iptables.Modules.IpSet
{
    public class SetMatchModule : ModuleBase, IEquatable<SetMatchModule>, IIpTablesModule
    {
        public enum MatchMode
        {
            None,
            Equal,
            NotEqual,
            Gt,
            Lt
        }

        private const string OptionMatchSet = "--match-set";
        private const string OptionNoMatch = "--return-nomatch";
        private const string OptionUpdateCounters = "--update-counters";
        private const string OptionUpdateSubCounters = "--update-subcounters";
        private const string OptionPacketsEq = "--packets-eq";
        private const string OptionPacketsLt = "--packets-lt";
        private const string OptionPacketsGt = "--packets-gt";
        private const string OptionBytesEq = "--bytes-eq";
        private const string OptionBytesLt = "--bytes-lt";
        private const string OptionBytesGt = "--bytes-gt";

        public ValueOrNot<string> MatchSet;
        public string MatchSetFlags;
        public bool ReturnNoMatch;
        public bool UpdateCounters = true;
        public bool UpdateSubCounters = true;
        private int _packetsValue;
        public MatchMode PacketsMatch = MatchMode.None;
        private int _bytesValue;
        public MatchMode BytesMatch = MatchMode.None;

        public SetMatchModule(int version) : base(version)
        {
        }

        public int BytesValue
        {
            get => _bytesValue;
            set
            {
                _bytesValue = value;
                if (BytesMatch == MatchMode.None) BytesMatch = MatchMode.Equal;
            }
        }

        public int PacketsValue
        {
            get => _packetsValue;
            set
            {
                _packetsValue = value;
                if (PacketsMatch == MatchMode.None) PacketsMatch = MatchMode.Equal;
            }
        }

        public bool Equals(SetMatchModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Equals(MatchSet, other.MatchSet) && string.Equals(MatchSetFlags, other.MatchSetFlags) &&
                   ReturnNoMatch.Equals(other.ReturnNoMatch) && UpdateCounters.Equals(other.UpdateCounters) &&
                   UpdateSubCounters.Equals(other.UpdateSubCounters) && _packetsValue == other._packetsValue &&
                   PacketsMatch == other.PacketsMatch && _bytesValue == other._bytesValue &&
                   BytesMatch == other.BytesMatch;
        }

        public int Feed(CommandParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionMatchSet:
                    MatchSet = new ValueOrNot<string>(parser.GetNextArg(), not);
                    MatchSetFlags = parser.GetNextArg(2);
                    return 2;
                case OptionNoMatch:
                    ReturnNoMatch = !not;
                    break;
                case OptionUpdateCounters:
                    UpdateCounters = !not;
                    break;
                case OptionUpdateSubCounters:
                    UpdateSubCounters = !not;
                    break;
                case OptionPacketsEq:
                    PacketsMatch = not ? MatchMode.NotEqual : MatchMode.Equal;
                    PacketsValue = int.Parse(parser.GetNextArg());
                    return 1;
                case OptionBytesEq:
                    BytesMatch = not ? MatchMode.NotEqual : MatchMode.Equal;
                    BytesValue = int.Parse(parser.GetNextArg());
                    return 1;
                case OptionPacketsLt:
                    PacketsMatch = MatchMode.Lt;
                    PacketsValue = int.Parse(parser.GetNextArg());
                    return 1;
                case OptionBytesLt:
                    BytesMatch = MatchMode.Lt;
                    BytesValue = int.Parse(parser.GetNextArg());
                    return 1;
                case OptionPacketsGt:
                    PacketsMatch = MatchMode.Gt;
                    PacketsValue = int.Parse(parser.GetNextArg());
                    return 1;
                case OptionBytesGt:
                    BytesMatch = MatchMode.Gt;
                    BytesValue = int.Parse(parser.GetNextArg());
                    return 1;
            }

            return 0;
        }

        public bool NeedsLoading => true;

        private string GetMatch(string type, MatchMode mode)
        {
            switch (mode)
            {
                case MatchMode.Equal:
                    return "--" + type + "-eq";
                case MatchMode.NotEqual:
                    return "! --" + type + "-eq";
                case MatchMode.Lt:
                    return "--" + type + "-lt";
                case MatchMode.Gt:
                    return "--" + type + "-gt";
            }

            throw new Exception("Unknown match mode type, should not happen");
        }

        public string GetRuleString()
        {
            var sb = new StringBuilder();

            if (!MatchSet.Null)
            {
                sb.Append((MatchSet.Not ? "! " : "") + OptionMatchSet + " " +
                          ShellHelper.EscapeArguments(MatchSet.Value));
                sb.Append(" " + MatchSetFlags);
            }

            if (ReturnNoMatch) sb.Append(" " + OptionNoMatch);

            if (!UpdateCounters) sb.Append(" ! " + OptionUpdateCounters);

            if (!UpdateSubCounters) sb.Append(" ! " + OptionUpdateSubCounters);

            if (PacketsMatch != MatchMode.None) sb.Append(" " + GetMatch("packets", PacketsMatch) + " " + PacketsValue);

            if (BytesMatch != MatchMode.None) sb.Append(" " + GetMatch("bytes", BytesMatch) + " " + BytesValue);

            return sb.ToString();
        }

        public static HashSet<string> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionMatchSet,
                OptionNoMatch,
                OptionUpdateCounters,
                OptionUpdateSubCounters,
                OptionPacketsEq,
                OptionPacketsLt,
                OptionPacketsGt,
                OptionBytesEq,
                OptionBytesLt,
                OptionBytesGt
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("set", typeof(SetMatchModule), GetOptions, (version) => new SetMatchModule(version));
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((SetMatchModule) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = MatchSet.GetHashCode();
                hashCode = (hashCode * 397) ^ (MatchSetFlags != null ? MatchSetFlags.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ ReturnNoMatch.GetHashCode();
                hashCode = (hashCode * 397) ^ UpdateCounters.GetHashCode();
                hashCode = (hashCode * 397) ^ UpdateSubCounters.GetHashCode();
                hashCode = (hashCode * 397) ^ _packetsValue;
                hashCode = (hashCode * 397) ^ (int) PacketsMatch;
                hashCode = (hashCode * 397) ^ _bytesValue;
                hashCode = (hashCode * 397) ^ (int) BytesMatch;
                return hashCode;
            }
        }
    }
}