using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.IpSet
{
    public class IpSetModule : ModuleBase, IEquatable<IpSetModule>, IIpTablesModuleGod
    {
        public enum MatchMode
        {
            None,
            Equal,
            NotEqual,
            Gt,
            Lt
        }

        private const String OptionMatchSet = "--match-set";
        private const String OptionNoMatch = "--return-nomatch";
        private const String OptionUpdateCounters = "--update-counters";
        private const String OptionUpdateSubCounters = "--update-subcounters";
        private const String OptionPacketsEq = "--packets-eq";
        private const String OptionPacketsLt = "--packets-lt";
        private const String OptionPacketsGt = "--packets-gt";
        private const String OptionBytesEq = "--bytes-eq";
        private const String OptionBytesLt = "--bytes-lt";
        private const String OptionBytesGt = "--bytes-gt";

        public ValueOrNot<String> MatchSet;
        public bool ReturnNoMatch;
        public bool UpdateCounters = true;
        public bool UpdateSubCounters = true;
        private int _packetsValue;
        public MatchMode PacketsMatch = MatchMode.None;
        private int _bytesValue;
        public MatchMode BytesMatch = MatchMode.None;

        public int BytesValue
        {
            get { return _bytesValue; }
            set
            {
                _bytesValue = value;
                if (BytesMatch == MatchMode.None)
                {
                    BytesMatch = MatchMode.Equal;
                }
            }
        }

        public int PacketsValue
        {
            get { return _packetsValue; }
            set
            {
                _packetsValue = value;
                if (PacketsMatch == MatchMode.None)
                {
                    PacketsMatch = MatchMode.Equal;
                }
            }
        }

        public bool Equals(IpSetModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return MatchSet.Equals(other.MatchSet);
        }

        int IIpTablesModuleInternal.Feed(RuleParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionMatchSet:
                    MatchSet = new ValueOrNot<String>(parser.GetNextArg(), not);
                    return 1;
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

        public bool NeedsLoading
        {
            get { return true; }
        }

        private String GetMatch(String type, MatchMode mode)
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

        public String GetRuleString()
        {
            StringBuilder sb = new StringBuilder();
            
            sb.Append(MatchSet.ToOption(OptionMatchSet));

            if (ReturnNoMatch)
            {
                sb.Append(" " + OptionNoMatch);
            }

            if (!UpdateCounters)
            {
                sb.Append(" ! " + OptionUpdateCounters);
            }

            if (!UpdateSubCounters)
            {
                sb.Append(" ! " + OptionUpdateSubCounters);
            }

            if (PacketsMatch != MatchMode.None)
            {
                sb.Append(" " + GetMatch("packets", PacketsMatch) + " " + PacketsValue);
            }

            if (BytesMatch != MatchMode.None)
            {
                sb.Append(" " + GetMatch("bytes", BytesMatch) + " " + BytesValue);
            }

            return sb.ToString();
        }

        public static IEnumerable<String> GetOptions()
        {
            var options = new List<string>
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
            return GetModuleEntryInternal("set", typeof(IpSetModule), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((IpSetModule)obj);
        }

        public override int GetHashCode()
        {
            return MatchSet.GetHashCode();
        }
    }
}