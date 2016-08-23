using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Recent
{
    public class RecentModule : ModuleBase, IIpTablesModule, IEquatable<RecentModule>
    {
        private static IPAddress IPv6Max = IPAddress.Parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");

        private const String OptionNameLong = "--name";
        private const String OptionSetLong = "--set";
        private const String OptionRsourceLong = "--rsource";
        private const String OptionRdestLong = "--rdest";
        private const String OptionRcheckLong = "--rcheck";
        private const String OptionUpdateLong = "--update";
        private const String OptionRemoveLong = "--remove";
        private const String OptionSecondsLong = "--seconds";
        private const String OptionReapLong = "--reap";
        private const String OptionHitcountLong = "--hitcount";
        private const String OptionRttlLong = "--rttl";
        private const String OptionMaskLong = "--mask";
        public int? HitCount;

        public ValueOrNot<RecentMode> Mode = new ValueOrNot<RecentMode>();
        public String Name = "DEFAULT";

        public bool Reap;
        public bool Rsource = true;

        public bool Rttl;
        public int? Seconds = null;
        public IPAddress Mask = IPAddress.Broadcast;
        private int _version;

        public bool Rdest
        {
            get { return !Rsource; }
            set { Rsource = !value; }
        }

        public RecentModule(int version) : base(version)
        {
            _version = version;
            if (version == 6)
            {
                Mask = IPv6Max;
            }
        }

        public bool Equals(RecentModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            
            return Mode.Equals(other.Mode) && string.Equals(Name, other.Name) && Rsource.Equals(other.Rsource) &&
                   Seconds == other.Seconds && Reap.Equals(other.Reap) && HitCount == other.HitCount &&
                   Rttl.Equals(other.Rttl) && Mask.Equals(other.Mask);
        }

        public bool NeedsLoading
        {
            get { return true; }
        }

        public int Feed(RuleParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionNameLong:
                    Name = parser.GetNextArg();
                    return 1;
                case OptionSetLong:
                    Mode = new ValueOrNot<RecentMode>(RecentMode.Set);
                    return 0;
                case OptionRsourceLong:
                    Rsource = true;
                    return 0;
                case OptionRdestLong:
                    Rdest = true;
                    return 0;
                case OptionRcheckLong:
                    Mode = new ValueOrNot<RecentMode>(RecentMode.Rcheck);
                    return 0;
                case OptionUpdateLong:
                    Mode = new ValueOrNot<RecentMode>(RecentMode.Update);
                    return 0;
                case OptionRemoveLong:
                    Mode = new ValueOrNot<RecentMode>(RecentMode.Remove);
                    return 0;
                case OptionSecondsLong:
                    Seconds = int.Parse(parser.GetNextArg());
                    return 1;
                case OptionReapLong:
                    Reap = true;
                    return 0;
                case OptionHitcountLong:
                    HitCount = int.Parse(parser.GetNextArg());
                    return 1;
                case OptionRttlLong:
                    Rttl = true;
                    return 0;
                case OptionMaskLong:
                    var oldAf = Mask.AddressFamily;
                    Mask = IPAddress.Parse(parser.GetNextArg());
                    if (Mask.AddressFamily != oldAf)
                    {
                        throw new IpTablesNetException("Invalid address family for mask "+parser.GetNextArg()+" should be "+oldAf);
                    }
                    return 1;
            }

            return 0;
        }

        public String GetRuleString()
        {
            var sb = new StringBuilder();

            if (!Mode.Null)
            {
                if (sb.Length != 0)
                    sb.Append(" ");

                switch (Mode.Value)
                {
                    case RecentMode.Set:
                        sb.Append(Mode.ToOption(OptionSetLong, ""));
                        break;
                    case RecentMode.Rcheck:
                        sb.Append(Mode.ToOption(OptionRcheckLong, ""));
                        break;
                    case RecentMode.Update:
                        sb.Append(Mode.ToOption(OptionUpdateLong, ""));
                        break;
                    case RecentMode.Remove:
                        sb.Append(Mode.ToOption(OptionRemoveLong, ""));
                        break;
                }
            }

            if (!String.IsNullOrEmpty(Name) && Name != "DEFAULT")
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(OptionNameLong);
                sb.Append(" ");
                sb.Append(Name);
            }

            if (!(Equals(Mask, _version == 4 ? IPAddress.Broadcast : IPv6Max)))
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(OptionMaskLong);
                sb.Append(" ");
                sb.Append(Mask);
            }

            if (Rdest)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(OptionRdestLong);
            }

            if (Seconds != null)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(OptionSecondsLong);
                sb.Append(" ");
                sb.Append(Seconds);
            }

            if (HitCount != null)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(OptionHitcountLong);
                sb.Append(" ");
                sb.Append(HitCount);
            }

            if (Reap)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(OptionReapLong);
            }

            if (Rttl)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(OptionRttlLong);
            }

            return sb.ToString();
        }

        public static HashSet<String> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionNameLong,
                OptionSetLong,
                OptionRsourceLong,
                OptionRdestLong,
                OptionRcheckLong,
                OptionUpdateLong,
                OptionRemoveLong,
                OptionSecondsLong,
                OptionReapLong,
                OptionHitcountLong,
                OptionRttlLong,
                OptionMaskLong
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("recent", typeof (RecentModule), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((RecentModule) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = (Mode != null ? Mode.GetHashCode() : 0);
                hashCode = (hashCode*397) ^ (Name != null ? Name.GetHashCode() : 0);
                hashCode = (hashCode*397) ^ Rsource.GetHashCode();
                hashCode = (hashCode*397) ^ Seconds.GetHashCode();
                hashCode = (hashCode*397) ^ Reap.GetHashCode();
                hashCode = (hashCode*397) ^ HitCount.GetHashCode();
                hashCode = (hashCode * 397) ^ Rttl.GetHashCode();
                hashCode = (hashCode * 397) ^ Mask.GetHashCode();
                return hashCode;
            }
        }
    }
}