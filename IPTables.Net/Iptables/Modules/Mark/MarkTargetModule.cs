using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Mark
{
    public class MarkTargetModule : ModuleBase, IIpTablesModuleGod, IEquatable<MarkTargetModule>
    {
        private const String OptionSetMarkLong = "--set-mark";
        private const String OptionSetXMarkLong = "--set-xmark";

        // mnemonics
        private const String OptionSetAndMarkLong = "--and-mark";
        private const String OptionSetOrMarkLong = "--or-mark";
        private const String OptionSetXorMarkLong = "--xor-mark";

        private const int DefaultMask = unchecked ((int) 0xFFFFFFFF);

        private bool _markProvided = false;
        private int _mark = 0;
        private int _mask = unchecked((int)0xFFFFFFFF);

        public MarkTargetModule(int version) : base(version)
        {
        }

        public void SetXMark(int value, int mask = unchecked ((int)0xFFFFFFFF))
        {
            _mark = value;
            _mask = mask;
            _markProvided = true;
        }

        public void SetAndMark(int value)
        {
            SetXMark(0, ~value);
        }

        public void SetOrMark(int value)
        {
            SetXMark(value, value);
        }

        public void SetXorMark(int value)
        {
            SetXMark(value, 0);
        }

        public void SetMark(int value, int mask)
        {
            _mark = value;
            _mask = mask | value;
            _markProvided = true;
        }

        public bool Equals(MarkTargetModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return _markProvided.Equals(other._markProvided) && _mark == other._mark && _mask == other._mask;
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
                case OptionSetXorMarkLong:
                    bits = FlexibleInt32.Parse(parser.GetNextArg());
                    SetXorMark(bits);
                    return 1;

                case OptionSetAndMarkLong:
                    bits = FlexibleInt32.Parse(parser.GetNextArg());
                    SetAndMark(bits);
                    return 1;

                case OptionSetOrMarkLong:
                    bits = FlexibleInt32.Parse(parser.GetNextArg());
                    SetOrMark(bits);
                    return 1;

                case OptionSetMarkLong:
                    var s1 = parser.GetNextArg().Split('/');

                    SetMark(FlexibleInt32.Parse(s1[0]), s1.Length == 1?DefaultMask:FlexibleInt32.Parse(s1[1]));
                    return 1;

                case OptionSetXMarkLong:
                    var s2 = parser.GetNextArg().Split('/');

                    SetXMark(FlexibleInt32.Parse(s2[0]), s2.Length == 1?DefaultMask:FlexibleInt32.Parse(s2[1]));
                    return 1;
            }

            return 0;
        }

        public String GetRuleString()
        {
            var sb = new StringBuilder();

            if (_markProvided)
            {
                sb.Append(OptionSetXMarkLong + " ");
                sb.Append("0x");
                sb.Append(_mark.ToString("X"));
                if (_mask != unchecked ((int)0xFFFFFFFF))
                {
                    sb.Append("/0x");
                    sb.Append(_mask.ToString("X"));
                }
            }

            return sb.ToString();
        }

        public static IEnumerable<String> GetOptions()
        {
            var options = new List<string>
            {
                OptionSetMarkLong,
                OptionSetXMarkLong,
                OptionSetAndMarkLong,
                OptionSetOrMarkLong,
                OptionSetXorMarkLong
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetTargetModuleEntryInternal("MARK", typeof (MarkTargetModule), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((MarkTargetModule) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode =  _markProvided.GetHashCode();
                hashCode = (hashCode*397) ^ _mark;
                hashCode = (hashCode*397) ^ _mask;
                return hashCode;
            }
        }
    }
}