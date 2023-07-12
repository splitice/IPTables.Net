using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Limit
{
    public class LimitModule : ModuleBase, IIpTablesModule, IEquatable<LimitModule>
    {
        private const string OptionLimit = "--limit";
        private const string OptionLimitBurst = "--limit-burst";
        public int Burst = 5;

        public int LimitRate = 3;
        public LimitUnit Unit = LimitUnit.Hour;

        public const uint Hz = 250;
        public const uint LimitScale = 10000;

        private static uint _POW2_BELOW2(uint x)
        {
            return x | (x >> 1);
        }

        private static uint _POW2_BELOW4(uint x)
        {
            return _POW2_BELOW2(x) | _POW2_BELOW2(x >> 2);
        }

        private static uint _POW2_BELOW8(uint x)
        {
            return _POW2_BELOW4(x) | _POW2_BELOW4(x >> 4);
        }

        private static uint _POW2_BELOW16(uint x)
        {
            return _POW2_BELOW8(x) | _POW2_BELOW8(x >> 8);
        }

        private static uint _POW2_BELOW32(uint x)
        {
            return _POW2_BELOW16(x) | _POW2_BELOW16(x >> 16);
        }

        private static uint POW2_BELOW32(uint x)
        {
            return (_POW2_BELOW32(x) >> 1) + 1;
        }

        public LimitModule(int version) : base(version)
        {
        }

        public bool Equals(LimitModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return CompareRate((uint) LimitRate, (uint) other.LimitRate, Unit) && Unit == other.Unit &&
                   Burst == other.Burst;
        }


        public static bool CompareRate(uint a, uint b, LimitUnit unit)
        {
            a = ComparablyReduce(a, unit);
            b = ComparablyReduce(b, unit);

            return a == b;
        }

        private static uint ComparablyReduce(uint a, LimitUnit unit)
        {
            a = LimitScale / (a * LimitScaleFactor(unit));
            const uint MaxCpj = 0xFFFFFFFF / (Hz * 60 * 60 * 24);
            var cpj = POW2_BELOW32(MaxCpj);

            if (a > 0xFFFFFFFF / (Hz * cpj)) return a / LimitScale * Hz * cpj;

            var credits = a * Hz * cpj / LimitScale;
            return credits;
        }

        public bool NeedsLoading => true;

        public int Feed(CommandParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionLimit:
                    var s = parser.GetNextArg().Split(new[] {'/'});
                    LimitRate = int.Parse(s[0]);
                    if (s.Length == 2)
                        Unit = GetUnit(s[1]);
                    else if (s.Length > 2) throw new IpTablesNetException("Invalid limit format");
                    return 1;

                case OptionLimitBurst:
                    Burst = int.Parse(parser.GetNextArg());
                    return 1;
            }

            return 0;
        }

        public string GetRuleString()
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

        private LimitUnit GetUnit(string strUnit)
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
                case LimitUnit.Hour: return 60 * 60;
                case LimitUnit.Day: return 60 * 60 * 24;
            }

            return 0;
        }

        private string GetUnit(LimitUnit limitUnit)
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

        public static HashSet<string> GetOptions()
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
            return GetModuleEntryInternal("limit", typeof(LimitModule), GetOptions, (version) => new LimitModule(version));
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((LimitModule) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = LimitRate;
                hashCode = (hashCode * 397) ^ (int) Unit;
                hashCode = (hashCode * 397) ^ Burst;
                return hashCode;
            }
        }
    }
}