using System;
using System.Collections.Generic;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Helper
{
    public class HelperModule : ModuleBase, IEquatable<HelperModule>, IIpTablesModuleGod
    {
        private const String OptionHelperLong = "--helper";

        public ValueOrNot<String> Helper;

        public HelperModule(int version) : base(version)
        {
        }

        public bool Equals(HelperModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Helper.Equals(other.Helper);
        }

        int IIpTablesModuleInternal.Feed(RuleParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionHelperLong:
                    Helper = new ValueOrNot<String>(parser.GetNextArg(), not);
                    return 1;
            }

            return 0;
        }

        public bool NeedsLoading
        {
            get { return true; }
        }

        public String GetRuleString()
        {
            return Helper.ToOption(OptionHelperLong);
        }

        public static IEnumerable<String> GetOptions()
        {
            var options = new List<string>
            {
                OptionHelperLong
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("helper", typeof(HelperModule), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((HelperModule)obj);
        }

        public override int GetHashCode()
        {
            return Helper.GetHashCode();
        }
    }
}