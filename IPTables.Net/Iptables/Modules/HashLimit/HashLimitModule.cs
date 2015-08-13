using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.DataTypes;
using IPTables.Net.Iptables.Helpers;

namespace IPTables.Net.Iptables.Modules.HashLimit
{
    public class HashLimitModule : ModuleBase, IIpTablesModule, IEquatable<HashLimitModule>
    {
        private const String OptionHashLimit = "--hashlimit";
        private const String OptionHashLimitUpto = "--hashlimit-upto";
        private const String OptionHashLimitAbove = "--hashlimit-above";
        private const String OptionHashLimitBurst = "--hashlimit-burst";
        private const String OptionHashLimitName = "--hashlimit-name";
        private const String OptionHashLimitMode = "--hashlimit-mode";
        private const String OptionHashLimitSrcMask = "--hashlimit-srcmask";
        private const String OptionHashLimitDstMask = "--hashlimit-dstmask";
        private const String OptionHashLimitHtableSize = "--hashlimit-htable-size";
        private const String OptionHashLimitHtableMax = "--hashlimit-htable-max";
        private const String OptionHashLimitHtableExpire = "--hashlimit-htable-expire";
        private const String OptionHashLimitHtableGcInterval = "--hashlimit-htable-gcinterval"; 

        public int Burst = 5;

        public String Name;
        public int LimitRate = 3;
        public LimitUnit Unit = LimitUnit.Hour;
        public HashLimitMode LimitMode = HashLimitMode.Upto;
        public String Mode = "";
        public int SrcMask = 32;
        public int DstMask = 32;
        public int HtableSize = 65000;
        public int HtableMax = 30000;
        public int HtableExpire = 10000;
        public int HtableGcInterval = 1000;

        public HashLimitModule(int version) : base(version)
        {
        }

        public bool Equals(HashLimitModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Burst == other.Burst && string.Equals(Name, other.Name) && CompareRate((UInt32)LimitRate, (UInt32)other.LimitRate) && Unit == other.Unit && LimitMode == other.LimitMode && string.Equals(Mode, other.Mode) && SrcMask == other.SrcMask && DstMask == other.DstMask && HtableSize == other.HtableSize && HtableMax == other.HtableMax && HtableExpire == other.HtableExpire && HtableGcInterval == other.HtableGcInterval;
        }

        public static bool CompareRate(UInt32 a, UInt32 b)
        {
            if (a >= 5000)
            {
                a = 10000;
            }
            if (b >= 5000)
            {
                b = 10000;
            }
            a = (a/10000);
            b = (b/10000);

            return a == b;
        }

        public bool NeedsLoading
        {
            get { return true; }
        }

        public int Feed(RuleParser parser, bool not)
        {
            String current = parser.GetCurrentArg();
            switch (current)
            { 
                case OptionHashLimitMode:
                    Mode = parser.GetNextArg();
                    return 1;
                case OptionHashLimitSrcMask:
                    SrcMask = int.Parse(parser.GetNextArg());
                    return 1;
                case OptionHashLimitDstMask:
                    DstMask = int.Parse(parser.GetNextArg());
                    return 1;
                case OptionHashLimitHtableSize:
                    HtableSize = int.Parse(parser.GetNextArg());
                    return 1;
                case OptionHashLimitHtableMax:
                    HtableMax = int.Parse(parser.GetNextArg());
                    return 1;
                case OptionHashLimitHtableExpire:
                    HtableExpire = int.Parse(parser.GetNextArg());
                    return 1;
                case OptionHashLimitHtableGcInterval:
                    HtableGcInterval = int.Parse(parser.GetNextArg());
                    return 1;

                case OptionHashLimitName:
                    Name = parser.GetNextArg();
                    if (Name.Length > 15)
                    {
                        Name = Name.Substring(0, 15);
                    }
                    return 1;

                case OptionHashLimit:
                case OptionHashLimitAbove:
                case OptionHashLimitUpto:
                    string[] s = parser.GetNextArg().Split(new[] {'/'});
                    LimitRate = int.Parse(s[0]);
                    if (s.Length == 2)
                    {
                        Unit = GetUnit(s[1]);
                    }
                    else if (s.Length > 2)
                    {
                        throw new IpTablesNetException("Invalid limit format");
                    }

                    LimitMode = current == OptionHashLimitAbove ? HashLimitMode.Above : HashLimitMode.Upto;

                    return 1;

                case OptionHashLimitBurst:
                    Burst = int.Parse(parser.GetNextArg());
                    return 1;
            }

            return 0;
        }

        public String GetRuleString()
        {
            var sb = new StringBuilder();

            sb.Append(OptionHashLimitName);
            sb.Append(" ");
            sb.Append(ShellHelper.EscapeArguments(Name));

            sb.Append(" ");
            if (LimitMode == HashLimitMode.Upto)
            {
                sb.Append(OptionHashLimitUpto);
            }
            else
            {
                sb.Append(OptionHashLimitAbove);
            }
            sb.Append(" ");
            sb.Append(LimitRate);
            sb.Append("/");
            sb.Append(GetUnit(Unit));

            sb.Append(" ");
            sb.Append(OptionHashLimitBurst);
            sb.Append(" ");
            sb.Append(Burst);

            sb.Append(" ");
            sb.Append(OptionHashLimitMode);
            sb.Append(" ");
            sb.Append(Mode);

            sb.Append(" ");
            sb.Append(OptionHashLimitSrcMask);
            sb.Append(" ");
            sb.Append(SrcMask);

            sb.Append(" ");
            sb.Append(OptionHashLimitDstMask);
            sb.Append(" ");
            sb.Append(DstMask);

            sb.Append(" ");
            sb.Append(OptionHashLimitHtableSize);
            sb.Append(" ");
            sb.Append(HtableSize);

            sb.Append(" ");
            sb.Append(OptionHashLimitHtableMax);
            sb.Append(" ");
            sb.Append(HtableMax);

            sb.Append(" ");
            sb.Append(OptionHashLimitHtableExpire);
            sb.Append(" ");
            sb.Append(HtableExpire);

            sb.Append(" ");
            sb.Append(OptionHashLimitHtableGcInterval);
            sb.Append(" ");
            sb.Append(HtableGcInterval);

            return sb.ToString();
        }

        private LimitUnit GetUnit(String strUnit)
        {
            switch (strUnit)
            {
                case "s":
                case "sec":
                case "second":
                    return LimitUnit.Second;
                case "m":
                case "min":
                case "minute":
                    return LimitUnit.Minute;
                case "h":
                case "hour":
                    return LimitUnit.Hour;
                case "d":
                case "day":
                    return LimitUnit.Day;
            }

            throw new IpTablesNetException("Invalid limit unit");
        }

        private String GetUnit(LimitUnit limitUnit)
        {
            switch (limitUnit)
            {
                case LimitUnit.Second:
                    return "second";
                    break;
                case LimitUnit.Minute:
                    return "minute";
                    break;
                case LimitUnit.Hour:
                    return "hour";
                case LimitUnit.Day:
                    return "day";
            }

            throw new IpTablesNetException("Invalid hashlimit unit");
        }

        public static HashSet<String> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionHashLimit,
                OptionHashLimitAbove,
                OptionHashLimitUpto,
                OptionHashLimitBurst,
                OptionHashLimitDstMask,
                OptionHashLimitHtableExpire,
                OptionHashLimitHtableGcInterval,
                OptionHashLimitHtableMax,
                OptionHashLimitHtableSize,
                OptionHashLimitMode,
                OptionHashLimitName,
                OptionHashLimitSrcMask
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("hashlimit", typeof (HashLimitModule), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((HashLimitModule) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = Burst;
                hashCode = (hashCode * 397) ^ (Name != null ? Name.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ LimitRate;
                hashCode = (hashCode * 397) ^ (int)Unit;
                hashCode = (hashCode * 397) ^ (int)LimitMode;
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