using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Mark
{
    public class MarkLoadableModule : ModuleBase, IIpTablesModuleGod, IEquatable<MarkLoadableModule>
    {
        //TODO: Proper mark implementation
        private const String OptionMarkLong = "--mark";

        public ValueOrNot<int> Mark = new ValueOrNot<int>();

        public bool NeedsLoading
        {
            get
            {
                return true;
            }
        }

        int IIpTablesModuleInternal.Feed(RuleParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionMarkLong:
                    Mark.Set(not, FlexibleInt.Parse(parser.GetNextArg()));
                    return 1;
            }

            return 0;
        }

        public String GetRuleString()
        {
            var sb = new StringBuilder();

            if (!Mark.Null)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(Mark.ToOption(OptionMarkLong));
            }

            return sb.ToString();
        }

        public static IEnumerable<String> GetOptions()
        {
            var options = new List<string>
                          {
                              OptionMarkLong
                          };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("mark", typeof(MarkLoadableModule), GetOptions);
        }

        public bool Equals(MarkLoadableModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Mark.Equals(other.Mark);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((MarkLoadableModule) obj);
        }

        public override int GetHashCode()
        {
            return Mark.GetHashCode();
        }
    }
}