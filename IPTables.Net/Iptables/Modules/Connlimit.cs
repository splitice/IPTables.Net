using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Iptables.Modules.Base;

namespace IPTables.Net.Iptables.Modules
{
    public class Connlimit : ModuleBase, IIptablesModule, IEquatable<Connlimit>
    {
        private const String OptionUpto = "--connlimit-upto";
        private const String OptionAbove = "--connlimit-above";
        private const String OptionMask = "--connlimit-mask";
        private const String OptionSourceAddr = "--connlimit-saddr";
        private const String OptionDestinationAddr = "--connlimit-daddr";

        public int Above = -1;

        public AddrMode LimitMatch = AddrMode.Source;
        public int Mask = -1;
        public int Upto = -1;

        public int Feed(RuleParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionUpto:
                    Upto = int.Parse(parser.GetNextArg());
                    return 1;

                case OptionAbove:
                    Above = int.Parse(parser.GetNextArg());
                    return 1;
                case OptionMask:
                    Mask = int.Parse(parser.GetNextArg());
                    return 1;

                case OptionSourceAddr:
                    LimitMatch = AddrMode.Source;
                    return 0;

                case OptionDestinationAddr:
                    LimitMatch = AddrMode.Target;
                    return 0;
            }

            return 0;
        }

        public String GetRuleString()
        {
            var sb = new StringBuilder();

            if (Upto != -1)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append("--connlimit-upto ");
                sb.Append(Upto);
            }

            if (Above != -1)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append("--connlimit-above ");
                sb.Append(Above);
            }

            if (Mask != -1)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append("--connlimit-mask ");
                sb.Append(Mask);
            }

            if (LimitMatch != AddrMode.Source)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(OptionDestinationAddr);
            }

            return sb.ToString();
        }

        public static IEnumerable<String> GetOptions()
        {
            var options = new List<string>
                          {
                              OptionUpto,
                              OptionAbove,
                              OptionMask,
                              OptionSourceAddr,
                              OptionDestinationAddr
                          };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("connlimit", typeof (Connlimit), GetOptions);
        }

        public enum AddrMode
        {
            Source,
            Target
        }

        public bool Equals(Connlimit other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Above == other.Above && LimitMatch == other.LimitMatch && Mask == other.Mask && Upto == other.Upto;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((Connlimit) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = Above;
                hashCode = (hashCode*397) ^ (int) LimitMatch;
                hashCode = (hashCode*397) ^ Mask;
                hashCode = (hashCode*397) ^ Upto;
                return hashCode;
            }
        }
    }
}