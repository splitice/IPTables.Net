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
            Add,
            Del,
            Map
        }

        private const string OptionAddSet = "--add-set";
        private const string OptionDelSet = "--del-set";
        private const string OptionMapSet = "--map-set";
        private const string OptionExist = "--exist";
        private const string OptionTimeout = "--timeout";

        public ValueOrNot<string> MatchSet;
        public string MatchSetFlags;
        public MatchMode MatchSetMode;
        public bool Exist;
        public int Timeout = -1;

        public SetTargetModule(int version) : base(version)
        {
        }

        public int Feed(CommandParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionAddSet:
                    MatchSet = new ValueOrNot<string>(parser.GetNextArg(), not);
                    MatchSetFlags = parser.GetNextArg(2);
                    MatchSetMode = MatchMode.Add;
                    return 2;
                case OptionDelSet:
                    MatchSet = new ValueOrNot<string>(parser.GetNextArg(), not);
                    MatchSetFlags = parser.GetNextArg(2);
                    MatchSetMode = MatchMode.Del;
                    return 2;
                case OptionMapSet:
                    MatchSet = new ValueOrNot<string>(parser.GetNextArg(), not);
                    MatchSetFlags = parser.GetNextArg(2);
                    MatchSetMode = MatchMode.Map;
                    return 2;
                case OptionExist:
                    Exist = true;
                    return 0;
                case OptionTimeout:
                    Timeout = int.Parse(parser.GetNextArg());
                    return 1;
            }

            return 0;
        }

        public bool NeedsLoading => false;

        public string GetRuleString()
        {
            var sb = new StringBuilder();

            if (!MatchSet.Null)
            {
                var option = OptionAddSet;
                if (MatchSetMode == MatchMode.Del) option = OptionDelSet;
                if (MatchSetMode == MatchMode.Map) option = OptionMapSet;
                sb.Append(option + " " + ShellHelper.EscapeArguments(MatchSet.Value));
                sb.Append(" " + MatchSetFlags);
            }

            if (Exist) sb.Append(" " + OptionExist);

            if (Timeout >= 0) sb.Append(" " + OptionTimeout + " " + Timeout);

            return sb.ToString();
        }

        public static HashSet<string> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionAddSet, OptionDelSet, OptionMapSet, OptionExist, OptionTimeout
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
            return MatchSet.Equals(other.MatchSet) && string.Equals(MatchSetFlags, other.MatchSetFlags) &&
                   MatchSetMode == other.MatchSetMode && Exist == other.Exist && Timeout == other.Timeout;
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
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