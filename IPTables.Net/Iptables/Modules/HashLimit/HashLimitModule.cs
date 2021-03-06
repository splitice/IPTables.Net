﻿using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.DataTypes;
using IPTables.Net.Iptables.Helpers;

namespace IPTables.Net.Iptables.Modules.HashLimit
{
    public class HashLimitModule : ModuleBase, IIpTablesModule, IEquatable<HashLimitModule>
    {
        private const String OptionHashLimit = "--hashlimit";
        private const String OptionHashLimitUpto = "--hashlimit-upto";
        private const String OptionHashLimitAbove = "--hashlimit-above";
        private const String OptionHashLimitBurst = "--hashlimit-burst";
        private const String OptionHashLimitName = "--hashlimit-name";
        private const String OptionHashLimitMode = "--hashlimit-mode";
        private const String OptionHashLimitSrcMask = "--hashlimit-srcmask";
        private const String OptionHashLimitDstMask = "--hashlimit-dstmask";
        private const String OptionHashLimitHtableSize = "--hashlimit-htable-size";
        private const String OptionHashLimitHtableMax = "--hashlimit-htable-max";
        private const String OptionHashLimitHtableExpire = "--hashlimit-htable-expire";
        private const String OptionHashLimitHtableGcInterval = "--hashlimit-htable-gcinterval";

        private const int DefaultMaskIpv4 = 32;
        private const int DefaultMaskIpv6 = 128;
        private char _scale = 'b';

        public const UInt16 ByteShift = 4;

        public UInt64 Burst { get; set; } = 5;

        public String Name { get; set; }
        public UInt64 LimitRate { get; set; } = 3;
        public LimitUnit Unit { get; set; } = LimitUnit.Hour;
        public HashLimitMode LimitMode { get; set; } = HashLimitMode.Upto | HashLimitMode.Packets;
        public String Mode { get; set; } = "";
        public int SrcMask { get; set; }
        public int DstMask { get; set; }
        public int HtableSize { get; set; } = 65000;
        public int HtableMax { get; set; } = 200000;
        public int HtableExpire { get; set; } = 10000;
        public int HtableGcInterval { get; set; } = 1000;
        public char Scale { get => _scale; set => _scale = value; }

        public const UInt32 Hz = 250;
        public const UInt64 LimitScale = 1000000;

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


        private static UInt32 _POW2_BELOW2(UInt32 x)
        {
            return ((x) | ((x) >> 1));
        }
        private static UInt32 _POW2_BELOW4(UInt32 x)
        {
            return (HashLimitModule._POW2_BELOW2(x) | _POW2_BELOW2((x) >> 2));
        }
        private static UInt32 _POW2_BELOW8(UInt32 x)
        {
            return (HashLimitModule._POW2_BELOW4(x) | HashLimitModule._POW2_BELOW4((x) >> 4));
        }
        private static UInt32 _POW2_BELOW16(UInt32 x)
        {
            return (HashLimitModule._POW2_BELOW8(x) | HashLimitModule._POW2_BELOW8((x) >> 8));
        }
        private static UInt32 _POW2_BELOW32(UInt32 x)
        {
            return (HashLimitModule._POW2_BELOW16(x) | HashLimitModule._POW2_BELOW16((x) >> 16));
        }
        private static UInt32 POW2_BELOW32(UInt32 x)
        {
            return ((HashLimitModule._POW2_BELOW32(x) >> 1) + 1);
        }

        public bool Equals(HashLimitModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Burst == other.Burst && string.Equals(Name, other.Name) && CompareRate(LimitMode, LimitRate, other.LimitRate, Unit) && Unit == other.Unit && LimitMode == other.LimitMode && string.Equals(Mode, other.Mode) && SrcMask == other.SrcMask && DstMask == other.DstMask && HtableSize == other.HtableSize && HtableMax == other.HtableMax && HtableExpire == other.HtableExpire && HtableGcInterval == other.HtableGcInterval;
        }

        private static ulong ComparablyReduce(ulong a, LimitUnit unit)
        {
            a = HashLimitModule.LimitScale / (a * HashLimitModule.LimitScaleFactor(unit));
            const UInt32 MaxCpj = 0xFFFFFFFF / HashLimitModule.Hz;
            UInt64 credits = (a * HashLimitModule.Hz * HashLimitModule.POW2_BELOW32(MaxCpj)) / HashLimitModule.LimitScale;
            return credits;
        }

        public static bool CompareRate(HashLimitMode mode, UInt64 a, UInt64 b, LimitUnit unit)
        {
            if ((mode & HashLimitMode.Bytes) == 0)
            {
                var a32 = ComparablyReduce(a, unit);
                var b32 = ComparablyReduce(b, unit);

                return a32 == b32;
            }

            return a == b;
        }

        public bool NeedsLoading
        {
            get { return true; }
        }

        private UInt64 ParseByte(String b, ref char scale)
        {
            b = b.ToLower();
            String ub = b.Substring(b.Length - 2, 2);


            UInt64 ret = 0;
            switch (ub)
            {
                case "gb":
                    ret = UInt64.Parse(b.Substring(0, b.Length - 2));
                    if (scale == 'b') ub = "g";
                    break;
                case "mb":
                    ret = UInt64.Parse(b.Substring(0, b.Length - 2));
                    if (scale == 'b') ub = "m";
                    break;
                case "kb":
                    ret = UInt64.Parse(b.Substring(0, b.Length - 2));
                    if (scale == 'b') ub = "k";
                    break;
                default:
                    if (b.EndsWith('b')) b = b.Substring(0, b.Length - 1);
                    ret = UInt64.Parse(b);
                    ub = "b";
                    break;
            }

            if (scale == 'b')
            {
                scale = ub[0];
            }

            return ret;
        }

        public int Feed(CommandParser parser, bool not)
        {
            String current = parser.GetCurrentArg();
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
                    if (Name.Length > 15)
                    {
                        Name = Name.Substring(0, 15);
                    }
                    return 1;

                case OptionHashLimit:
                case OptionHashLimitAbove:
                case OptionHashLimitUpto:
                    string[] s = parser.GetNextArg().Split(new[] { '/' });
                    if (s[0].EndsWith("b"))
                    {
                        LimitMode |= HashLimitMode.Bytes;
                        LimitRate = RoundByte(ParseByte(s[0], ref _scale));
                    }
                    else
                    {
                        LimitRate = UInt64.Parse(s[0]);
                    }

                    if (s.Length == 2)
                    {
                        Unit = GetUnit(s[1]);
                    }
                    else if (s.Length > 2)
                    {
                        throw new IpTablesNetException("Invalid limit format");
                    }

                    LimitMode |= current == OptionHashLimitAbove ? HashLimitMode.Above : HashLimitMode.Upto;

                    return 1;

                case OptionHashLimitBurst:
                    if ((LimitMode & HashLimitMode.Bytes) == HashLimitMode.Bytes)
                    {
                        Burst = ParseByte(parser.GetNextArg(), ref _scale);
                        Burst = (Burst / LimitRate) * LimitRate;
                    }
                    else
                    {
                        Burst = UInt64.Parse(parser.GetNextArg());
                    }

                    return 1;
            }

            return 0;
        }

        public static ulong RoundByte(ulong bytes, UInt32 mult)
        {
            bytes *= mult;
            UInt32 r32 = (UInt32)(bytes >> ByteShift);
            UInt64 cost = UInt32.MaxValue / (r32 + 1);
            UInt64 r = (cost!=0) ? UInt32.MaxValue / cost : UInt32.MaxValue;
            r = (r - 1) << ByteShift;
            r /= mult;
            return r;
        }
        private ulong RoundByte(ulong bytes)
        {
            var mult = GetMultiplyScale();
            return RoundByte(bytes, mult);
        }

        public UInt32 GetMultiplyScale()
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

        public String GetRuleString()
        {
            var sb = new StringBuilder();

            sb.Append(OptionHashLimitName);
            sb.Append(" ");
            sb.Append(ShellHelper.EscapeArguments(Name));

            sb.Append(" ");
            if (LimitMode == HashLimitMode.Upto)
            {
                sb.Append(OptionHashLimitUpto);
            }
            else
            {
                sb.Append(OptionHashLimitAbove);
            }
            sb.Append(" ");
            if ((LimitMode & HashLimitMode.Bytes) == HashLimitMode.Bytes)
            {
                OutputByte(sb, LimitRate);
            }
            else
            {
                sb.Append(LimitRate);
            }
            sb.Append("/");
            sb.Append(GetUnit(Unit));

            sb.Append(" ");
            sb.Append(OptionHashLimitBurst);
            sb.Append(" ");
            if ((LimitMode & HashLimitMode.Bytes) == HashLimitMode.Bytes)
            {
                OutputByte(sb, Burst);
            }
            else
            {
                sb.Append(Burst);
            }

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

        private LimitUnit GetUnit(String strUnit)
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

        private String GetUnit(LimitUnit limitUnit)
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

        public static HashSet<String> GetOptions()
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
            if (obj.GetType() != this.GetType()) return false;
            return Equals((HashLimitModule)obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = Burst.GetHashCode();
                hashCode = (hashCode * 397) ^ (Name != null ? Name.GetHashCode() : 0);
                hashCode = (hashCode * 397) ^ LimitRate.GetHashCode();
                hashCode = (hashCode * 397) ^ (int)Unit;
                hashCode = (hashCode * 397) ^ (int)LimitMode;
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