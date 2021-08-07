using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Mark
{
    public class MarkMatchModule : ModuleBase, IIpTablesModule, IEquatable<MarkMatchModule>
    {
        private const string OptionMarkLong = "--mark";

        public ValueOrNot<UInt32Masked> Mark = new ValueOrNot<UInt32Masked>(new UInt32Masked(0, UInt32.MaxValue));

        public MarkMatchModule(int version) : base(version)
        {
        }

        public bool Equals(MarkMatchModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Equals(Mark, other.Mark);
        }

        public bool NeedsLoading => true;

        public int Feed(CommandParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionMarkLong:
                    Mark.Set(not, UInt32Masked.Parse(parser.GetNextArg()));
                    return 1;
            }

            return 0;
        }

        public string GetRuleString()
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

        public static HashSet<string> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionMarkLong
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("mark", typeof(MarkMatchModule), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((MarkMatchModule) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return Mark.GetHashCode();
            }
        }
    }
}