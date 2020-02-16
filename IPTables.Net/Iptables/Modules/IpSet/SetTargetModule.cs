using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.DataTypes;
using IPTables.Net.Iptables.Helpers;

namespace IPTables.Net.Iptables.Modules.IpSet
{
    public class SetTargetModule : ModuleBase, IEquatable<SetTargetModule>, IIpTablesModule
    {
        public enum MatchMode
        {
            Add, Del, Map
        }

        private const String OptionAddSet = "--add-set";
        private const String OptionDelSet = "--del-set";
        private const String OptionMapSet = "--map-set";

        public ValueOrNot<String> MatchSet;
        public String MatchSetFlags;
        public MatchMode MatchSetMode;

        public SetTargetModule(int version) : base(version)
        {
        }

        public int Feed(RuleParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionAddSet:
                    MatchSet = new ValueOrNot<String>(parser.GetNextArg(), not);
                    MatchSetFlags = parser.GetNextArg(2);
                    MatchSetMode = MatchMode.Add;
                    return 2;
                case OptionDelSet:
                    MatchSet = new ValueOrNot<String>(parser.GetNextArg(), not);
                    MatchSetFlags = parser.GetNextArg(2);
                    MatchSetMode = MatchMode.Del;
                    return 2;
                case OptionMapSet:
                    MatchSet = new ValueOrNot<String>(parser.GetNextArg(), not);
                    MatchSetFlags = parser.GetNextArg(2);
                    MatchSetMode = MatchMode.Map;
                    return 2;
            }

            return 0;
        }

        public bool NeedsLoading
        {
            get { return false; }
        }

        public String GetRuleString()
        {
            StringBuilder sb = new StringBuilder();

            if (!MatchSet.Null)
            {
                String option = OptionAddSet;
                if (MatchSetMode == MatchMode.Del) option = OptionDelSet;
                if (MatchSetMode == MatchMode.Map) option = OptionMapSet;
                sb.Append(option + " " + ShellHelper.EscapeArguments(MatchSet.Value));
                sb.Append(" " + MatchSetFlags);
            }

            return sb.ToString();
        }

        public static HashSet<String> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionAddSet, OptionDelSet, OptionMapSet
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetTargetModuleEntryInternal("SET", typeof(SetTargetModule), GetOptions);
        }

        public bool Equals(SetTargetModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return MatchSet.Equals(other.MatchSet) && string.Equals(MatchSetFlags, other.MatchSetFlags) && MatchSetMode == other.MatchSetMode;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((SetTargetModule) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = MatchSet.GetHashCode();
                hashCode = (hashCode * 397) ^ (MatchSetFlags != null ? MatchSetFlags.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ (int) MatchSetMode;
                return hashCode;
            }
        }
    }
}