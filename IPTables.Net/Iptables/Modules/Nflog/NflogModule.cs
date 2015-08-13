using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Iptables.Helpers;

namespace IPTables.Net.Iptables.Modules.Nflog
{
    public class NflogModule : ModuleBase, IEquatable<NflogModule>, IIpTablesModule
    {
        private const String OptionPrefixLong = "--nflog-prefix";
        private const String OptionGroupLong = "--nflog-group";
        private const String OptionRangeLong = "--nflog-range";
        private const String OptionThresholdLong = "--nflog-threshold";

        
        public int LogGroup = 0;
        public String LogPrefix;
        public int? LogRange = null;
        public int LogThreshold = 1;


        public NflogModule(int version) : base(version)
        {
        }

        public int Feed(RuleParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionPrefixLong:
                    LogPrefix = parser.GetNextArg();
                    return 1;
                case OptionGroupLong:
                    LogGroup = int.Parse(parser.GetNextArg());
                    return 1;
                case OptionRangeLong:
                    LogRange = int.Parse(parser.GetNextArg());
                    return 1;
                case OptionThresholdLong:
                    LogThreshold = int.Parse(parser.GetNextArg());
                    return 1;
            }

            return 0;
        }

        public bool NeedsLoading
        {
            get { return false; }
        }

        public String GetRuleString()
        {
            var sb = new StringBuilder();

            if (LogGroup != 0)
            {
                sb.Append(OptionGroupLong + " ");
                sb.Append(LogGroup);
            }

            if (LogPrefix != null)
            {
                if (sb.Length != 0) sb.Append(" ");
                sb.Append(OptionPrefixLong + " ");
                sb.Append(ShellHelper.EscapeArguments(LogPrefix));
            }

            if (LogRange != null)
            {
                if (sb.Length != 0) sb.Append(" ");
                sb.Append(OptionRangeLong + " ");
                sb.Append(LogRange);
            }

            if (LogThreshold != 1)
            {
                if (sb.Length != 0) sb.Append(" ");
                sb.Append(OptionThresholdLong + " ");
                sb.Append(LogThreshold);
            }

            return sb.ToString();
        }

        public static HashSet<String> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionGroupLong,
                OptionPrefixLong,
                OptionRangeLong,
                OptionThresholdLong
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetTargetModuleEntryInternal("NFLOG", typeof(NflogModule), GetOptions);
        }

        public bool Equals(NflogModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return string.Equals(LogPrefix, other.LogPrefix) && LogGroup == other.LogGroup && LogRange == other.LogRange && LogThreshold == other.LogThreshold;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((NflogModule) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = (LogPrefix != null ? LogPrefix.GetHashCode() : 0);
                hashCode = (hashCode*397) ^ LogGroup;
                hashCode = (hashCode*397) ^ LogRange.GetHashCode();
                hashCode = (hashCode*397) ^ LogThreshold;
                return hashCode;
            }
        }
    }
}