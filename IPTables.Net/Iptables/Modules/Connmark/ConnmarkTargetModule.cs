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

        private const int DefaultMask = unchecked((int) 0xFFFFFFFF);

        private bool _markProvided = false;
        private int _value = 0;
        private int _mask = unchecked((int) 0xFFFFFFFF);
        private int _ctMask;
        private int _nfMask;
        private Mode _mode = Mode.SetMark;

        public ConnmarkTargetModule(int version) : base(version)
        {
        }

        public void SetXMark(int value, int mask = unchecked((int) 0xFFFFFFFF))
        {
            _value = value;
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
            _value = value;
            _mask = mask | value;
            _markProvided = true;
        }

        public bool Equals(ConnmarkTargetModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return _markProvided.Equals(other._markProvided) && _value == other._value && _mask == other._mask &&
                   _nfMask == other._nfMask && _ctMask == other._ctMask && _mode == other._mode;
        }

        public bool NeedsLoading => false;

        public int Feed(CommandParser parser, bool not)
        {
            int bits;
            switch (parser.GetCurrentArg())
            {
                case OptionSetXorMarkLong:
                    _mode = Mode.SetMark;
                    bits = FlexibleInt32.Parse(parser.GetNextArg());
                    SetXorMark(bits);
                    return 1;

                case OptionSetAndMarkLong:
                    _mode = Mode.SetMark;
                    bits = FlexibleInt32.Parse(parser.GetNextArg());
                    SetAndMark(bits);
                    return 1;

                case OptionSetOrMarkLong:
                    _mode = Mode.SetMark;
                    bits = FlexibleInt32.Parse(parser.GetNextArg());
                    SetOrMark(bits);
                    return 1;

                case OptionSetMarkLong:
                    _mode = Mode.SetMark;
                    var s1 = parser.GetNextArg().Split('/');

                    SetMark(FlexibleInt32.Parse(s1[0]), s1.Length == 1 ? DefaultMask : FlexibleInt32.Parse(s1[1]));
                    return 1;

                case OptionSetXMarkLong:
                    _mode = Mode.SetMark;
                    var s2 = parser.GetNextArg().Split('/');

                    SetXMark(FlexibleInt32.Parse(s2[0]), s2.Length == 1 ? DefaultMask : FlexibleInt32.Parse(s2[1]));
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
                    sb.Append("0x");
                    sb.Append(_value.ToString("X"));
                    if (_mask != unchecked((int) 0xFFFFFFFF))
                    {
                        sb.Append("/0x");
                        sb.Append(_mask.ToString("X"));
                    }
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
                var hashCode = _markProvided.GetHashCode();
                hashCode = (hashCode * 397) ^ _value;
                hashCode = (hashCode * 397) ^ _mask;
                hashCode = (hashCode * 397) ^ _ctMask;
                hashCode = (hashCode * 397) ^ _nfMask;
                hashCode = (hashCode * 397) ^ _mode.GetHashCode();
                return hashCode;
            }
        }
    }
}