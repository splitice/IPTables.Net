using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Connmark
{
    public class ConnmarkMatchModule : ModuleBase, IIpTablesModule, IEquatable<ConnmarkMatchModule>
    {
        private const string OptionMarkLong = "--mark";
        private ValueOrNot<UInt32Masked> _mark = new ValueOrNot<UInt32Masked>();

        public ValueOrNot<UInt32Masked> Mark
        {
            get => _mark;
            set => _mark = value;
        }

        public ConnmarkMatchModule(int version) : base(version)
        {
        }

        public bool Equals(ConnmarkMatchModule other)
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
                    _mark = new ValueOrNot<UInt32Masked>(UInt32Masked.Parse(parser.GetNextArg()), not);
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
            return GetModuleEntryInternal("connmark", typeof(ConnmarkMatchModule), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((ConnmarkMatchModule) obj);
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