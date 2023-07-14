using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Mark
{
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors | DynamicallyAccessedMemberTypes.PublicMethods | DynamicallyAccessedMemberTypes.PublicProperties | DynamicallyAccessedMemberTypes.NonPublicFields)]
    public class MarkTargetModule : ModuleBase, IIpTablesModule, IEquatable<MarkTargetModule>
    {
        private const string OptionSetMarkLong = "--set-mark";
        private const string OptionSetXMarkLong = "--set-xmark";

        // mnemonics
        private const string OptionSetAndMarkLong = "--and-mark";
        private const string OptionSetOrMarkLong = "--or-mark";
        private const string OptionSetXorMarkLong = "--xor-mark";

        public const UInt32 DefaultMask = unchecked((UInt32) 0xFFFFFFFF);

        private bool _markProvided = false;
        private UInt32Masked _mark = new UInt32Masked(0, DefaultMask);

        public MarkTargetModule(int version) : base(version)
        {
        }

        public void SetXMark(UInt32 value, UInt32 mask = unchecked((UInt32) 0xFFFFFFFF))
        {
            _mark = new UInt32Masked(value, mask);
            _markProvided = true;
        }

        public void SetAndMark(UInt32 value)
        {
            SetXMark(0, ~value);
        }

        public void SetOrMark(UInt32 value)
        {
            SetXMark(value, value);
        }

        public void SetXorMark(UInt32 value)
        {
            SetXMark(value, 0);
        }

        public void SetMark(UInt32 value, UInt32 mask)
        {
            _mark = new UInt32Masked(value, mask | value);
            _markProvided = true;
        }

        public bool Equals(MarkTargetModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return _markProvided.Equals(other._markProvided) && _mark.Equals(other._mark);
        }

        public bool NeedsLoading => false;

        public int Feed(CommandParser parser, bool not)
        {
            UInt32 bits;
            switch (parser.GetCurrentArg())
            {
                case OptionSetXorMarkLong:
                    bits = FlexibleUInt32.Parse(parser.GetNextArg());
                    SetXorMark(bits);
                    return 1;

                case OptionSetAndMarkLong:
                    bits = FlexibleUInt32.Parse(parser.GetNextArg());
                    SetAndMark(bits);
                    return 1;

                case OptionSetOrMarkLong:
                    bits = FlexibleUInt32.Parse(parser.GetNextArg());
                    SetOrMark(bits);
                    return 1;

                case OptionSetMarkLong:
                    var s1 = parser.GetNextArg().Split('/');

                    SetMark(FlexibleUInt32.Parse(s1[0]), s1.Length == 1 ? DefaultMask : FlexibleUInt32.Parse(s1[1]));
                    return 1;

                case OptionSetXMarkLong:
                    var s2 = parser.GetNextArg().Split('/');

                    SetXMark(FlexibleUInt32.Parse(s2[0]), s2.Length == 1 ? DefaultMask : FlexibleUInt32.Parse(s2[1]));
                    return 1;
            }

            return 0;
        }

        public string GetRuleString()
        {
            var sb = new StringBuilder();

            if (_markProvided)
            {
                sb.Append(OptionSetXMarkLong + " ");
                sb.Append(_mark.ToString());
            }

            return sb.ToString();
        }

        public static HashSet<string> GetOptions()
        {
            var options = new HashSet<string>
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
            return GetTargetModuleEntryInternal("MARK", typeof(MarkTargetModule), GetOptions, (version) => new MarkTargetModule(version));
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((MarkTargetModule) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = _markProvided.GetHashCode();
                hashCode = (hashCode * 397) ^ _mark.GetHashCode();
                return hashCode;
            }
        }
    }
}