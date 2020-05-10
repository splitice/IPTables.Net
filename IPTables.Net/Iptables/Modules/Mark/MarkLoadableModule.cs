using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Mark
{
    public class MarkLoadableModule : ModuleBase, IIpTablesModule, IEquatable<MarkLoadableModule>
    {
        private const String OptionMarkLong = "--mark";

        public ValueOrNot<int> Mark = new ValueOrNot<int>();
        public int Mask = unchecked ((int)0xFFFFFFFF);

        public MarkLoadableModule(int version) : base(version)
        {
        }

        public bool Equals(MarkLoadableModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Equals(Mark, other.Mark) && Mask == other.Mask;
        }

        public bool NeedsLoading
        {
            get { return true; }
        }

        public int Feed(CommandParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionMarkLong:
                    var s = parser.GetNextArg().Split(new char[] {'/'});
                    Mark.Set(not, FlexibleInt32.Parse(s[0]));
                    if (s.Length != 1)
                    {
                        Mask = FlexibleInt32.Parse(s[1]);
                    }
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
                if (Mask != unchecked((int) 0xFFFFFFFF))
                {
                    sb.Append("/0x");
                    sb.Append(Mask.ToString("X"));
                }
            }

            return sb.ToString();
        }

        public static HashSet<String> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionMarkLong
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("mark", typeof(MarkLoadableModule), GetOptions);
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
            unchecked
            {
                return (Mark.GetHashCode()*397) ^ Mask;
            }
        }
    }
}