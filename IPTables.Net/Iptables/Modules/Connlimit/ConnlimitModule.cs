using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace IPTables.Net.Iptables.Modules.Connlimit
{
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors | DynamicallyAccessedMemberTypes.PublicMethods | DynamicallyAccessedMemberTypes.PublicProperties | DynamicallyAccessedMemberTypes.NonPublicFields)]
    public class ConnlimitModule : ModuleBase, IIpTablesModule, IEquatable<ConnlimitModule>
    {
        public enum AddrMode
        {
            Source,
            Target
        }

        private const string OptionUpto = "--connlimit-upto";
        private const string OptionAbove = "--connlimit-above";
        private const string OptionMask = "--connlimit-mask";
        private const string OptionSourceAddr = "--connlimit-saddr";
        private const string OptionDestinationAddr = "--connlimit-daddr";

        public int Above { get; set; } = -1;

        public AddrMode LimitMatch { get; set; } = AddrMode.Source;
        public int Mask { get; set; } = -1;
        public int Upto { get; set; } = -1;

        public ConnlimitModule(int version) : base(version)
        {
        }

        public bool Equals(ConnlimitModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Above == other.Above && LimitMatch == other.LimitMatch && Mask == other.Mask && Upto == other.Upto;
        }

        public bool NeedsLoading => true;

        public int Feed(CommandParser parser, bool not)
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

        public string GetRuleString()
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

        public static HashSet<string> GetOptions()
        {
            var options = new HashSet<string>
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
            return GetModuleEntryInternal("connlimit", typeof(ConnlimitModule), GetOptions, (version) => new ConnlimitModule(version));
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((ConnlimitModule) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = Above;
                hashCode = (hashCode * 397) ^ (int) LimitMatch;
                hashCode = (hashCode * 397) ^ Mask;
                hashCode = (hashCode * 397) ^ Upto;
                return hashCode;
            }
        }
    }
}