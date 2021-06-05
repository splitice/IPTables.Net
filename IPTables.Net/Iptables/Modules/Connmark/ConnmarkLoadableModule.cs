using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Connmark
{
    public class ConnmarkLoadableModule : ModuleBase, IIpTablesModule, IEquatable<ConnmarkLoadableModule>
    {
        private const string OptionMarkLong = "--mark";
        private int _mask = unchecked((int) 0xFFFFFFFF);
        private ValueOrNot<int> _mark = new ValueOrNot<int>();

        public ValueOrNot<int> Mark
        {
            get => _mark;
            set => _mark = value;
        }

        public int Mask
        {
            get => _mask;
            set => _mask = value;
        }

        public ConnmarkLoadableModule(int version) : base(version)
        {
        }

        public bool Equals(ConnmarkLoadableModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Equals(Mark, other.Mark) && Mask == other.Mask;
        }

        public bool NeedsLoading => true;

        public int Feed(CommandParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionMarkLong:
                    var s = parser.GetNextArg().Split(new char[] {'/'});
                    _mark.Set(not, FlexibleInt32.Parse(s[0]));
                    if (s.Length != 1) _mask = FlexibleInt32.Parse(s[1]);
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
                if (Mask != unchecked((int) 0xFFFFFFFF))
                {
                    sb.Append("/0x");
                    sb.Append(Mask.ToString("X"));
                }
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
            return GetModuleEntryInternal("connmark", typeof(ConnmarkLoadableModule), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((ConnmarkLoadableModule) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return (Mark.GetHashCode() * 397) ^ Mask;
            }
        }
    }
}