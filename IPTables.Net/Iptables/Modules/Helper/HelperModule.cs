using System;
using System.Collections.Generic;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Helper
{
    public class HelperModule : ModuleBase, IEquatable<HelperModule>, IIpTablesModule
    {
        private const string OptionHelperLong = "--helper";

        public ValueOrNot<string> Helper;

        public HelperModule(int version) : base(version)
        {
        }

        public bool Equals(HelperModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Helper.Equals(other.Helper);
        }

        public int Feed(CommandParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionHelperLong:
                    Helper = new ValueOrNot<string>(parser.GetNextArg(), not);
                    return 1;
            }

            return 0;
        }

        public bool NeedsLoading => true;

        public string GetRuleString()
        {
            return Helper.ToOption(OptionHelperLong);
        }

        public static HashSet<string> GetOptions()
        {
            var options = new HashSet<string>
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
            return Equals((HelperModule) obj);
        }

        public override int GetHashCode()
        {
            return Helper.GetHashCode();
        }
    }
}