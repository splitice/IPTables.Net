using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.DataTypes;
using IPTables.Net.Iptables.Helpers;

namespace IPTables.Net.Iptables.Modules.HashRoute
{
    public class HashRouteTargetModule : ModuleBase, IIpTablesModule, IEquatable<HashRouteTargetModule>
    {
        private const String OptionHashRouteName = "--hashroute-name";
        private const String OptionHashRouteMode = "--hashroute-mode";
        private const String OptionHashRouteSrcMask = "--hashroute-srcmask";
        private const String OptionHashRouteDstMask = "--hashroute-dstmask";
        private const String OptionHashRouteHtableSize = "--hashroute-htable-size";
        private const String OptionHashRouteHtableMax = "--hashroute-htable-max";
        private const String OptionHashRouteHtableExpire = "--hashroute-htable-expire";
        private const String OptionHashRouteHtableGcInterval = "--hashroute-htable-gcinterval";

        private const int DefaultMaskIpv4 = 32;
        private const int DefaultMaskIpv6 = 128;

        public String Name;
        public String Mode = "";
        public int SrcMask;
        public int DstMask;
        public int HtableSize = 65000;
        public int HtableMax = 30000;
        public int HtableExpire = 10000;
        public int HtableGcInterval = 1000;

        public HashRouteTargetModule(int version) : base(version)
        {
            if (version == 4)
            {
                SrcMask = DefaultMaskIpv4;
                DstMask = DefaultMaskIpv4;
            }
            else if (version == 6)
            {
                SrcMask = DefaultMaskIpv6;
                DstMask = DefaultMaskIpv6;
            }
        }

        public bool Equals(HashRouteTargetModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return string.Equals(Name, other.Name) && string.Equals(Mode, other.Mode) && SrcMask == other.SrcMask && DstMask == other.DstMask && HtableSize == other.HtableSize && HtableMax == other.HtableMax && HtableExpire == other.HtableExpire && HtableGcInterval == other.HtableGcInterval;
        }

        public bool NeedsLoading
        {
            get { return false; }
        }

        public int Feed(RuleParser parser, bool not)
        {
            String current = parser.GetCurrentArg();
            switch (current)
            { 
                case OptionHashRouteMode:
                    Mode = parser.GetNextArg();
                    return 1;
                case OptionHashRouteSrcMask:
                    SrcMask = int.Parse(parser.GetNextArg());
                    return 1;
                case OptionHashRouteDstMask:
                    DstMask = int.Parse(parser.GetNextArg());
                    return 1;
                case OptionHashRouteHtableSize:
                    HtableSize = int.Parse(parser.GetNextArg());
                    return 1;
                case OptionHashRouteHtableMax:
                    HtableMax = int.Parse(parser.GetNextArg());
                    return 1;
                case OptionHashRouteHtableExpire:
                    HtableExpire = int.Parse(parser.GetNextArg());
                    return 1;
                case OptionHashRouteHtableGcInterval:
                    HtableGcInterval = int.Parse(parser.GetNextArg());
                    return 1;

                case OptionHashRouteName:
                    Name = parser.GetNextArg();
                    if (Name.Length > 15)
                    {
                        Name = Name.Substring(0, 15);
                    }
                    return 1;

            }

            return 0;
        }

        public String GetRuleString()
        {
            var sb = new StringBuilder();

            sb.Append(OptionHashRouteName);
            sb.Append(" ");
            sb.Append(ShellHelper.EscapeArguments(Name));

            sb.Append(" ");
            sb.Append(OptionHashRouteMode);
            sb.Append(" ");
            sb.Append(Mode);

            sb.Append(" ");
            sb.Append(OptionHashRouteSrcMask);
            sb.Append(" ");
            sb.Append(SrcMask);

            sb.Append(" ");
            sb.Append(OptionHashRouteDstMask);
            sb.Append(" ");
            sb.Append(DstMask);

            sb.Append(" ");
            sb.Append(OptionHashRouteHtableSize);
            sb.Append(" ");
            sb.Append(HtableSize);

            sb.Append(" ");
            sb.Append(OptionHashRouteHtableMax);
            sb.Append(" ");
            sb.Append(HtableMax);

            sb.Append(" ");
            sb.Append(OptionHashRouteHtableExpire);
            sb.Append(" ");
            sb.Append(HtableExpire);

            sb.Append(" ");
            sb.Append(OptionHashRouteHtableGcInterval);
            sb.Append(" ");
            sb.Append(HtableGcInterval);

            return sb.ToString();
        }

        public static HashSet<String> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionHashRouteDstMask,
                OptionHashRouteHtableExpire,
                OptionHashRouteHtableGcInterval,
                OptionHashRouteHtableMax,
                OptionHashRouteHtableSize,
                OptionHashRouteMode,
                OptionHashRouteName,
                OptionHashRouteSrcMask
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetTargetModuleEntryInternal("HASHROUTE", typeof(HashRouteTargetModule), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((HashRouteTargetModule) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = Name.GetHashCode();
                hashCode = (hashCode * 397) ^ (Mode != null ? Mode.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ SrcMask;
                hashCode = (hashCode * 397) ^ DstMask;
                hashCode = (hashCode * 397) ^ HtableSize;
                hashCode = (hashCode * 397) ^ HtableMax;
                hashCode = (hashCode * 397) ^ HtableExpire;
                hashCode = (hashCode * 397) ^ HtableGcInterval;
                return hashCode;
            }
        }

    }
}