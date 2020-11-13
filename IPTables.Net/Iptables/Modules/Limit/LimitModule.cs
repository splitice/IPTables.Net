using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Limit
{
    public class LimitModule : ModuleBase, IIpTablesModule, IEquatable<LimitModule>
    {
        private const String OptionLimit = "--limit";
        private const String OptionLimitBurst = "--limit-burst";
        public int Burst = 5;

        public int LimitRate = 3;
        public LimitUnit Unit = LimitUnit.Hour;

        public const UInt32 Hz = 250;
        public const UInt32 LimitScale = 10000;

        private static UInt32 _POW2_BELOW2(UInt32 x)
        {
            return ((x) | ((x) >> 1));
        }
        private static UInt32 _POW2_BELOW4(UInt32 x)
        {
            return (LimitModule._POW2_BELOW2(x) | _POW2_BELOW2((x) >> 2));
        }
        private static UInt32 _POW2_BELOW8(UInt32 x)
        {
            return (LimitModule._POW2_BELOW4(x) | LimitModule._POW2_BELOW4((x) >> 4));
        }
        private static UInt32 _POW2_BELOW16(UInt32 x)
        {
            return (LimitModule._POW2_BELOW8(x) | LimitModule._POW2_BELOW8((x) >> 8));
        }
        private static UInt32 _POW2_BELOW32(UInt32 x)
        {
            return (LimitModule._POW2_BELOW16(x) | LimitModule._POW2_BELOW16((x) >> 16));
        }
        private static UInt32 POW2_BELOW32(UInt32 x)
        {
            return ((LimitModule._POW2_BELOW32(x) >> 1) + 1);
        }

        public LimitModule(int version) : base(version)
        {
        }

        public bool Equals(LimitModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return CompareRate((UInt32)LimitRate, (UInt32)other.LimitRate, Unit) && Unit == other.Unit && Burst == other.Burst;
        }


        public static bool CompareRate(UInt32 a, UInt32 b, LimitUnit unit)
        {
            a = ComparablyReduce(a, unit);
            b = ComparablyReduce(b, unit);

            return a == b;
        }

        private static uint ComparablyReduce(uint a, LimitUnit unit)
        {
            a = LimitModule.LimitScale / (a * LimitModule.LimitScaleFactor(unit));
            const UInt32 MaxCpj = (0xFFFFFFFF / (LimitModule.Hz * 60 * 60 * 24));
            UInt32 cpj = LimitModule.POW2_BELOW32(MaxCpj);

            if (a > (0xFFFFFFFF / (LimitModule.Hz * cpj)))
            {
                return (a / LimitModule.LimitScale) * LimitModule.Hz * cpj;
            }

            UInt32 credits = (a * LimitModule.Hz * cpj) / LimitModule.LimitScale;
            return credits;
        }

        public bool NeedsLoading
        {
            get { return true; }
        }

        public int Feed(CommandParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionLimit:
                    string[] s = parser.GetNextArg().Split(new[] { '/' });
                    LimitRate = int.Parse(s[0]);
                    if (s.Length == 2)
                    {
                        Unit = GetUnit(s[1]);
                    }
                    else if (s.Length > 2)
                    {
                        throw new IpTablesNetException("Invalid limit format");
                    }
                    return 1;

                case OptionLimitBurst:
                    Burst = int.Parse(parser.GetNextArg());
                    return 1;
            }

            return 0;
        }

        public String GetRuleString()
        {
            var sb = new StringBuilder();

            sb.Append(OptionLimit);
            sb.Append(" ");
            sb.Append(LimitRate);
            sb.Append("/");
            sb.Append(GetUnit(Unit));

            sb.Append(" ");
            sb.Append(OptionLimitBurst);
            sb.Append(" ");
            sb.Append(Burst);

            return sb.ToString();
        }

        private LimitUnit GetUnit(String strUnit)
        {
            switch (strUnit)
            {
                case "second":
                case "sec":
                case "s":
                    return LimitUnit.Second;
                    break;
                case "minute":
                case "min":
                case "m":
                    return LimitUnit.Minute;
                    break;
                case "hour":
                case "h":
                    return LimitUnit.Hour;
                case "day":
                case "d":
                    return LimitUnit.Day;
            }

            throw new IpTablesNetException("Invalid limit unit");
        }

        public static uint LimitScaleFactor(LimitUnit unit)
        {
            switch (unit)
            {
                case LimitUnit.Second: return 1;
                case LimitUnit.Minute: return 60;
                case LimitUnit.Hour: return 60*60;
                case LimitUnit.Day: return 60 * 60 * 24;
            }

            return 0;
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

            throw new IpTablesNetException("Invalid limit unit");
        }

        public static HashSet<String> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionLimit,
                OptionLimitBurst
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("limit", typeof(LimitModule), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((LimitModule)obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = LimitRate;
                hashCode = (hashCode * 397) ^ (int)Unit;
                hashCode = (hashCode * 397) ^ Burst;
                return hashCode;
            }
        }
    }
}