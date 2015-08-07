using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Ct
{
    public class CtTargetModule : ModuleBase, IIpTablesModuleGod, IEquatable<CtTargetModule>
    {
        private const String OptionHelperLong = "--helper";

        private String Helper;

        public CtTargetModule(int version) : base(version)
        {
        }

        public bool Equals(CtTargetModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Helper.Equals(other.Helper);
        }

        public bool NeedsLoading
        {
            get { return false; }
        }

        int IIpTablesModuleInternal.Feed(RuleParser parser, bool not)
        {
            int bits;
            switch (parser.GetCurrentArg())
            {
                case OptionHelperLong:
                    Helper = parser.GetNextArg();
                    return 1;
            }

            return 0;
        }

        public String GetRuleString()
        {
            var sb = new StringBuilder();

            if (Helper != null)
            {
                sb.Append(OptionHelperLong + " ");
                sb.Append(Helper);
            }

            return sb.ToString();
        }

        public static HashSet<String> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionHelperLong
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetTargetModuleEntryInternal("CT", typeof(CtTargetModule), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((CtTargetModule)obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return Helper.GetHashCode();
            }
        }
    }
}