using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Connmark
{
    public class ConnmarkTargetModule : ModuleBase, IIpTablesModule, IEquatable<ConnmarkTargetModule>
    {
        private const string OptionRestoreMarkLong = "--restore-mark";
        private const string OptionSaveMarkLong = "--save-mark";
        private const string OptionNfMaskLong = "--nfmask";
        private const string OptionCtMaskLong = "--ctmask";

        private const string OptionSetMarkLong = "--set-mark";
        private const string OptionSetXMarkLong = "--set-xmark";

        // mnemonics
        private const string OptionSetAndMarkLong = "--and-mark";
        private const string OptionSetOrMarkLong = "--or-mark";
        private const string OptionSetXorMarkLong = "--xor-mark";

        private enum Mode
        {
            SetMark,
            RestoreMark,
            SaveMark
        }

        public const UInt32 DefaultMask = UInt32.MaxValue;
        private bool _markProvided = false;
        private UInt32Masked _value = new UInt32Masked(0, DefaultMask);

        private int _ctMask;
        private int _nfMask;
        private Mode _mode = Mode.SetMark;

        public ConnmarkTargetModule(int version) : base(version)
        {
        }

        public void SetXMark(UInt32 value, UInt32 mask = unchecked((UInt32) 0xFFFFFFFF))
        {
            _value = new UInt32Masked(value, mask);
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
            _value = new UInt32Masked(value, mask | value);
            _markProvided = true;
        }

        public bool Equals(ConnmarkTargetModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return _markProvided.Equals(other._markProvided) && _value.Equals(other._value) &&
                   _nfMask == other._nfMask && _ctMask == other._ctMask && _mode == other._mode;
        }

        public bool NeedsLoading => false;

        public int Feed(CommandParser parser, bool not)
        {
            UInt32 bits;
            switch (parser.GetCurrentArg())
            {
                case OptionSetXorMarkLong:
                    _mode = Mode.SetMark;
                    bits = FlexibleUInt32.Parse(parser.GetNextArg());
                    SetXorMark(bits);
                    return 1;

                case OptionSetAndMarkLong:
                    _mode = Mode.SetMark;
                    bits = FlexibleUInt32.Parse(parser.GetNextArg());
                    SetAndMark(bits);
                    return 1;

                case OptionSetOrMarkLong:
                    _mode = Mode.SetMark;
                    bits = FlexibleUInt32.Parse(parser.GetNextArg());
                    SetOrMark(bits);
                    return 1;

                case OptionSetMarkLong:
                    _mode = Mode.SetMark;
                    var s1 = parser.GetNextArg().Split('/');

                    SetMark(FlexibleUInt32.Parse(s1[0]), s1.Length == 1 ? DefaultMask : FlexibleUInt32.Parse(s1[1]));
                    return 1;

                case OptionSetXMarkLong:
                    _mode = Mode.SetMark;
                    var s2 = parser.GetNextArg().Split('/');

                    SetXMark(FlexibleUInt32.Parse(s2[0]), s2.Length == 1 ? DefaultMask : FlexibleUInt32.Parse(s2[1]));
                    return 1;

                case OptionRestoreMarkLong:
                    _mode = Mode.RestoreMark;
                    return 0;

                case OptionSaveMarkLong:
                    _mode = Mode.SaveMark;
                    return 0;

                case OptionCtMaskLong:
                    _ctMask = FlexibleInt32.Parse(parser.GetNextArg());
                    return 1;

                case OptionNfMaskLong:
                    _nfMask = FlexibleInt32.Parse(parser.GetNextArg());
                    return 1;
            }

            return 0;
        }

        public string GetRuleString()
        {
            var sb = new StringBuilder();

            if (_mode == Mode.SetMark)
            {
                if (_markProvided)
                {
                    sb.Append(OptionSetXMarkLong + " ");
                    sb.Append(_value.ToString());
                }
            }
            else
            {
                if (_mode == Mode.RestoreMark)
                    sb.Append(OptionRestoreMarkLong + " ");
                else
                    sb.Append(OptionSaveMarkLong + " ");
                sb.Append(OptionCtMaskLong + " 0x" + _ctMask.ToString("X") + " ");
                sb.Append(OptionNfMaskLong + " 0x" + _nfMask.ToString("X"));
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
                OptionSetXorMarkLong,
                OptionRestoreMarkLong,
                OptionSaveMarkLong,
                OptionNfMaskLong,
                OptionCtMaskLong
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetTargetModuleEntryInternal("CONNMARK", typeof(ConnmarkTargetModule), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((ConnmarkTargetModule) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = _value.GetHashCode();
                hashCode = (hashCode * 397) ^ _ctMask;
                hashCode = (hashCode * 397) ^ _nfMask;
                hashCode = (hashCode * 397) ^ _mode.GetHashCode();
                return hashCode;
            }
        }
    }
}