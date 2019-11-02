using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.TcpMss
{
    public class TcpMssMatchModule : ModuleBase, IIpTablesModule, IEquatable<TcpMssMatchModule>
    {
        private const String OptionMss= "--set-mss";

        public ValueOrNot<PortOrRange> MssRange;

        public TcpMssMatchModule(int version) : base(version)
        {
        }

        public bool Equals(TcpMssMatchModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return MssRange.Equals(other.MssRange);
        }

        public bool NeedsLoading
        {
            get { return true; }
        }

        public int Feed(RuleParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionMss:
                    var range = PortOrRange.Parse(parser.GetNextArg(), ':');
                    MssRange = new ValueOrNot<PortOrRange>(range, not);
                    return 1;
            }

            return 0;
        }

        public String GetRuleString()
        {
            return MssRange.ToOption(OptionMss);
        }

        public static HashSet<String> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionMss
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("tcpmss", typeof (TcpMssMatchModule), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((TcpMssMatchModule) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return MssRange.GetHashCode();
            }
        }
    }
}