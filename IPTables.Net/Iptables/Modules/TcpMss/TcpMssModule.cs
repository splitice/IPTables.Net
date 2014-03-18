using System;
using System.Collections.Generic;
using System.Text;

namespace IPTables.Net.Iptables.Modules.TcpMss
{
    public class TcpMssModule : ModuleBase, IIpTablesModuleGod, IEquatable<TcpMssModule>
    {
        private const String OptionClampMssToPmtuLong = "--clamp-mss-to-pmtu";

        public bool ClampMssToPmtu = false;

        public bool Equals(TcpMssModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return ClampMssToPmtu.Equals(other.ClampMssToPmtu);
        }

        public bool NeedsLoading
        {
            get { return false; }
        }

        int IIpTablesModuleInternal.Feed(RuleParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionClampMssToPmtuLong:
                    ClampMssToPmtu = true;
                    return 1;
            }

            return 0;
        }

        public String GetRuleString()
        {
            var sb = new StringBuilder();

            if (ClampMssToPmtu)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(OptionClampMssToPmtuLong);
            }

            return sb.ToString();
        }

        public static IEnumerable<String> GetOptions()
        {
            var options = new List<string>
            {
                OptionClampMssToPmtuLong
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetTargetModuleEntryInternal("TCPMSS", typeof (TcpMssModule), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((TcpMssModule) obj);
        }

        public override int GetHashCode()
        {
            return ClampMssToPmtu.GetHashCode();
        }
    }
}