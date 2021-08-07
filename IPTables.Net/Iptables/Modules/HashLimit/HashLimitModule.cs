using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.DataTypes;
using IPTables.Net.Iptables.Helpers;
using IPTables.Net.Supporting;

namespace IPTables.Net.Iptables.Modules.HashLimit
{
    public class HashLimitModule : ModuleBase, IIpTablesModule, IEquatable<HashLimitModule>
    {
        private const string OptionHashLimit = "--hashlimit";
        private const string OptionHashLimitUpto = "--hashlimit-upto";
        private const string OptionHashLimitAbove = "--hashlimit-above";
        private const string OptionHashLimitBurst = "--hashlimit-burst";
        private const string OptionHashLimitName = "--hashlimit-name";
        private const string OptionHashLimitMode = "--hashlimit-mode";
        private const string OptionHashLimitSrcMask = "--hashlimit-srcmask";
        private const string OptionHashLimitDstMask = "--hashlimit-dstmask";
        private const string OptionHashLimitHtableSize = "--hashlimit-htable-size";
        private const string OptionHashLimitHtableMax = "--hashlimit-htable-max";
        private const string OptionHashLimitHtableExpire = "--hashlimit-htable-expire";
        private const string OptionHashLimitHtableGcInterval = "--hashlimit-htable-gcinterval";

        private const int DefaultMaskIpv4 = 32;
        private const int DefaultMaskIpv6 = 128;
        private char _scale = 'b';

        public const ushort ByteShift = 4;

        public ulong Burst { get; set; } = 5;

        public string Name { get; set; }
        public ulong LimitRate { get; set; } = 3;
        public LimitUnit Unit { get; set; } = LimitUnit.Hour;
        public HashLimitMode LimitMode { get; set; } = HashLimitMode.Upto | HashLimitMode.Packets;
        public string Mode { get; set; } = "";
        public int SrcMask { get; set; }
        public int DstMask { get; set; }
        public int HtableSize { get; set; } = 65000;
        public int HtableMax { get; set; } = 200000;
        public int HtableExpire { get; set; } = 10000;
        public int HtableGcInterval { get; set; } = 1000;

        public char Scale
        {
            get => _scale;
            set => _scale = value;
        }

        public const uint Hz = 250;
        public const ulong LimitScale = 1000000;

        public HashLimitModule(int version) : base(version)
        {
            if (version == 4)
            {
                SrcMask = DefaultMaskIpv4;
                DstMask = DefaultMaskIpv4;
            }
            else if (version == 6)
            {
                SrcMask = DefaultMaskIpv6;
                DstMask = DefaultMaskIpv6;
            }
        }


        private static uint _POW2_BELOW2(uint x)
        {
            return x | (x >> 1);
        }

        private static uint _POW2_BELOW4(uint x)
        {
            return _POW2_BELOW2(x) | _POW2_BELOW2(x >> 2);
        }

        private static uint _POW2_BELOW8(uint x)
        {
            return _POW2_BELOW4(x) | _POW2_BELOW4(x >> 4);
        }

        private static uint _POW2_BELOW16(uint x)
        {
            return _POW2_BELOW8(x) | _POW2_BELOW8(x >> 8);
        }

        private static uint _POW2_BELOW32(uint x)
        {
            return _POW2_BELOW16(x) | _POW2_BELOW16(x >> 16);
        }

        private static uint POW2_BELOW32(uint x)
        {
            return (_POW2_BELOW32(x) >> 1) + 1;
        }

        public bool Equals(HashLimitModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Burst == other.Burst && string.Equals(Name, other.Name) &&
                   CompareRate(LimitMode, LimitRate, other.LimitRate, Unit) && Unit == other.Unit &&
                   LimitMode == other.LimitMode && string.Equals(Mode, other.Mode) && SrcMask == other.SrcMask &&
                   DstMask == other.DstMask && HtableSize == other.HtableSize && HtableMax == other.HtableMax &&
                   HtableExpire == other.HtableExpire && HtableGcInterval == other.HtableGcInterval;
        }

        private static ulong ComparablyReduce(ulong a, LimitUnit unit)
        {
            a = LimitScale / (a * LimitScaleFactor(unit));
            const uint MaxCpj = 0xFFFFFFFF / Hz;
            var credits = a * Hz * POW2_BELOW32(MaxCpj) / LimitScale;
            return credits;
        }

        public static bool CompareRate(HashLimitMode mode, ulong a, ulong b, LimitUnit unit)
        {
            if ((mode & HashLimitMode.Bytes) == 0)
            {
                var a32 = ComparablyReduce(a, unit);
                var b32 = ComparablyReduce(b, unit);

                return a32 == b32;
            }

            return a == b;
        }

        public bool NeedsLoading => true;

        private ulong ParseByte(string b, ref char scale)
        {
            b = b.ToLower();
            var ub = b.Substring(b.Length - 2, 2);


            ulong ret = 0;
            switch (ub)
            {
                case "gb":
                    ret = ulong.Parse(b.Substring(0, b.Length - 2));
                    if (scale == 'b') ub = "g";
                    break;
                case "mb":
                    ret = ulong.Parse(b.Substring(0, b.Length - 2));
                    if (scale == 'b') ub = "m";
                    break;
                case "kb":
                    ret = ulong.Parse(b.Substring(0, b.Length - 2));
                    if (scale == 'b') ub = "k";
                    break;
                default:
                    if (b.EndsWith('b')) b = b.Substring(0, b.Length - 1);
                    ret = ulong.Parse(b);
                    ub = "b";
                    break;
            }

            if (scale == 'b') scale = ub[0];

            return ret;
        }

        public int Feed(CommandParser parser, bool not)
        {
            var current = parser.GetCurrentArg();
            switch (current)
            {
                case OptionHashLimitMode:
                    Mode = parser.GetNextArg();
                    return 1;
                case OptionHashLimitSrcMask:
                    SrcMask = int.Parse(parser.GetNextArg());
                    return 1;
                case OptionHashLimitDstMask:
                    DstMask = int.Parse(parser.GetNextArg());
                    return 1;
                case OptionHashLimitHtableSize:
                    HtableSize = int.Parse(parser.GetNextArg());
                    return 1;
                case OptionHashLimitHtableMax:
                    HtableMax = int.Parse(parser.GetNextArg());
                    return 1;
                case OptionHashLimitHtableExpire:
                    HtableExpire = int.Parse(parser.GetNextArg());
                    return 1;
                case OptionHashLimitHtableGcInterval:
                    HtableGcInterval = int.Parse(parser.GetNextArg());
                    return 1;

                case OptionHashLimitName:
                    Name = parser.GetNextArg();
                    if (Name.Length > 15) Name = Name.Substring(0, 15);
                    return 1;

                case OptionHashLimit:
                case OptionHashLimitAbove:
                case OptionHashLimitUpto:
                    var s = parser.GetNextArg().Split(new[] {'/'});
                    if (s[0].EndsWith("b"))
                    {
                        LimitMode |= HashLimitMode.Bytes;
                        LimitRate = RoundByte(ParseByte(s[0], ref _scale));
                    }
                    else
                    {
                        LimitRate = ulong.Parse(s[0]);
                    }

                    if (s.Length == 2)
                        Unit = GetUnit(s[1]);
                    else if (s.Length > 2) throw new IpTablesNetException("Invalid limit format");

                    LimitMode |= current == OptionHashLimitAbove ? HashLimitMode.Above : HashLimitMode.Upto;

                    return 1;

                case OptionHashLimitBurst:
                    if ((LimitMode & HashLimitMode.Bytes) == HashLimitMode.Bytes)
                    {
                        Burst = ParseByte(parser.GetNextArg(), ref _scale);
                        Burst = Burst / LimitRate * LimitRate;
                    }
                    else
                    {
                        Burst = ulong.Parse(parser.GetNextArg());
                    }

                    return 1;
            }

            return 0;
        }

        public static ulong RoundByte(ulong bytes, uint mult)
        {
            bytes *= mult;
            var r32 = (uint) (bytes >> ByteShift);
            ulong cost = uint.MaxValue / (r32 + 1);
            var r = cost != 0 ? uint.MaxValue / cost : uint.MaxValue;
            r = (r - 1) << ByteShift;
            r /= mult;
            return r;
        }

        private ulong RoundByte(ulong bytes)
        {
            var mult = GetMultiplyScale();
            return RoundByte(bytes, mult);
        }

        public uint GetMultiplyScale()
        {
            switch (_scale)
            {
                case 'k':
                    return 1024;
                case 'm':
                    return 1024 * 1024;
                case 'g':
                    return 1024 * 1024 * 1024;
            }

            return 1;
        }

        public string GetRuleString()
        {
            var sb = new StringBuilder();

            sb.Append(OptionHashLimitName);
            sb.Append(" ");
            sb.Append(ShellHelper.EscapeArguments(Name));

            sb.Append(" ");
            if (LimitMode == HashLimitMode.Upto)
                sb.Append(OptionHashLimitUpto);
            else
                sb.Append(OptionHashLimitAbove);
            sb.Append(" ");
            if ((LimitMode & HashLimitMode.Bytes) == HashLimitMode.Bytes)
                OutputByte(sb, LimitRate);
            else
                sb.Append(LimitRate);
            sb.Append("/");
            sb.Append(GetUnit(Unit));

            sb.Append(" ");
            sb.Append(OptionHashLimitBurst);
            sb.Append(" ");
            if ((LimitMode & HashLimitMode.Bytes) == HashLimitMode.Bytes)
                OutputByte(sb, Burst);
            else
                sb.Append(Burst);

            sb.Append(" ");
            sb.Append(OptionHashLimitMode);
            sb.Append(" ");
            sb.Append(Mode);

            sb.Append(" ");
            sb.Append(OptionHashLimitSrcMask);
            sb.Append(" ");
            sb.Append(SrcMask);

            sb.Append(" ");
            sb.Append(OptionHashLimitDstMask);
            sb.Append(" ");
            sb.Append(DstMask);

            sb.Append(" ");
            sb.Append(OptionHashLimitHtableSize);
            sb.Append(" ");
            sb.Append(HtableSize);

            sb.Append(" ");
            sb.Append(OptionHashLimitHtableMax);
            sb.Append(" ");
            sb.Append(HtableMax);

            sb.Append(" ");
            sb.Append(OptionHashLimitHtableExpire);
            sb.Append(" ");
            sb.Append(HtableExpire);

            sb.Append(" ");
            sb.Append(OptionHashLimitHtableGcInterval);
            sb.Append(" ");
            sb.Append(HtableGcInterval);

            return sb.ToString();
        }

        private void OutputByte(StringBuilder sb, ulong limitRate)
        {
            sb.Append(limitRate);
            if (_scale != 'b') sb.Append(_scale);
            sb.Append("b");
        }

        private LimitUnit GetUnit(string strUnit)
        {
            switch (strUnit)
            {
                case "s":
                case "sec":
                case "second":
                    return LimitUnit.Second;
                case "m":
                case "min":
                case "minute":
                    return LimitUnit.Minute;
                case "h":
                case "hour":
                    return LimitUnit.Hour;
                case "d":
                case "day":
                    return LimitUnit.Day;
            }

            throw new IpTablesNetException("Invalid limit unit");
        }

        private string GetUnit(LimitUnit limitUnit)
        {
            switch (limitUnit)
            {
                case LimitUnit.Second:
                    return "second";
                    break;
                case LimitUnit.Minute:
                    return "minute";
                    break;
                case LimitUnit.Hour:
                    return "hour";
                case LimitUnit.Day:
                    return "day";
            }

            throw new IpTablesNetException("Invalid hashlimit unit");
        }

        public static uint LimitScaleFactor(LimitUnit unit)
        {
            switch (unit)
            {
                case LimitUnit.Second: return 1;
                case LimitUnit.Minute: return 60;
                case LimitUnit.Hour: return 60 * 60;
                case LimitUnit.Day: return 60 * 60 * 24;
            }

            return 0;
        }

        public static HashSet<string> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionHashLimit,
                OptionHashLimitAbove,
                OptionHashLimitUpto,
                OptionHashLimitBurst,
                OptionHashLimitDstMask,
                OptionHashLimitHtableExpire,
                OptionHashLimitHtableGcInterval,
                OptionHashLimitHtableMax,
                OptionHashLimitHtableSize,
                OptionHashLimitMode,
                OptionHashLimitName,
                OptionHashLimitSrcMask
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("hashlimit", typeof(HashLimitModule), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((HashLimitModule) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = Burst.GetHashCode();
                hashCode = (hashCode * 397) ^ (Name != null ? Name.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ LimitRate.GetHashCode();
                hashCode = (hashCode * 397) ^ (int) Unit;
                hashCode = (hashCode * 397) ^ (int) LimitMode;
                hashCode = (hashCode * 397) ^ (Mode != null ? Mode.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ SrcMask;
                hashCode = (hashCode * 397) ^ DstMask;
                hashCode = (hashCode * 397) ^ HtableSize;
                hashCode = (hashCode * 397) ^ HtableMax;
                hashCode = (hashCode * 397) ^ HtableExpire;
                hashCode = (hashCode * 397) ^ HtableGcInterval;
                return hashCode;
            }
        }
    }
}