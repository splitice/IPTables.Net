using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using IPTables.Net.Iptables.DataTypes;
using IPTables.Net.Iptables.Modules.Dnat;

namespace IPTables.Net.Iptables.Modules.SynProxy
{
    public class SynProxyModule : ModuleBase, IIpTablesModule, IEquatable<SynProxyModule>
    {
        private const String OptionMss = "--mss";
        private const String OptionWscale = "--wscale";
        private const String OptionSack = "--sack-perm";
        private const String OptionTimestamp = "--timestamp";

        public UInt16 Mss;
        public UInt16 Wscale;
        public bool Sack = false;
        public bool Timestamp = false;

        public SynProxyModule(int version) : base(version)
        {
        }

        public bool Equals(SynProxyModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Mss.Equals(other.Mss) && Wscale.Equals(other.Wscale) &&
                   Sack.Equals(other.Sack) && Timestamp.Equals(other.Timestamp);
        }

        public bool NeedsLoading
        {
            get { return false; }
        }

        public int Feed(RuleParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionMss:
                    Mss = UInt16.Parse(parser.GetNextArg());
                    return 1;

                case OptionWscale:
                    Wscale = UInt16.Parse(parser.GetNextArg());
                    return 1;

                case OptionSack:
                    Sack = true;
                    return 0;

                case OptionTimestamp:
                    Timestamp = true;
                    return 0;
            }

            return 0;
        }

        public String GetRuleString()
        {
            var sb = new StringBuilder();

            sb.Append(OptionMss + " ");
            sb.Append(Mss);
            sb.Append(" ");

            sb.Append(OptionWscale + " ");
            sb.Append(Wscale);

            if (Sack)
            {
                sb.Append(" ");
                sb.Append(OptionSack);
            }


            if (Timestamp)
            {
                sb.Append(" ");
                sb.Append(OptionTimestamp);
            }

            return sb.ToString();
        }

        public static HashSet<String> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionMss,
                OptionSack,
                OptionTimestamp,
                OptionWscale
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetTargetModuleEntryInternal("SYNPROXY", typeof (SynProxyModule), GetOptions, false);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((SynProxyModule)obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = Mss.GetHashCode();
                hashCode = (hashCode*397) ^ Wscale.GetHashCode();
                hashCode = (hashCode * 397) ^ Sack.GetHashCode();
                hashCode = (hashCode * 397) ^ Timestamp.GetHashCode();
                return hashCode;
            }
        }
    }
}