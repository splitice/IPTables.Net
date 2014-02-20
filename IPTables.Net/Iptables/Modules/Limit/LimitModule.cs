using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Limit
{
    public class LimitModule : ModuleBase, IIpTablesModuleGod, IEquatable<LimitModule>
    {
        private const String OptionLimit = "--limit";
        private const String OptionLimitBurst = "--limit-burst";

        public int LimitRate = 3;
        public LimitUnit Unit = LimitUnit.Hour;
        public int Burst = 5;

        public bool NeedsLoading
        {
            get
            {
                return true;
            }
        }

        private LimitUnit GetUnit(String strUnit)
        {
            switch (strUnit)
            {
                case "second":
                    return LimitUnit.Second;
                    break;
                case "minute":
                    return LimitUnit.Minute;
                    break;
                case "hour":
                    return LimitUnit.Hour;
                case "day":
                    return LimitUnit.Day;
            }

            throw new Exception("Invalid limit unit");
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

            throw new Exception("Invalid limit unit");
        }

        int IIpTablesModuleInternal.Feed(RuleParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionLimit:
                    var s = parser.GetNextArg().Split(new char[] {'/'});
                    LimitRate = int.Parse(s[0]);
                    if (s.Length == 2)
                    {
                        Unit = GetUnit(s[1]);
                    }
                    else if (s.Length > 2)
                    {
                        throw new Exception("Invalid limit format");
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

        public static IEnumerable<String> GetOptions()
        {
            var options = new List<string>
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

        public bool Equals(LimitModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return LimitRate == other.LimitRate && Unit == other.Unit && Burst == other.Burst;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((LimitModule) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = LimitRate;
                hashCode = (hashCode*397) ^ (int) Unit;
                hashCode = (hashCode*397) ^ Burst;
                return hashCode;
            }
        }
    }
}