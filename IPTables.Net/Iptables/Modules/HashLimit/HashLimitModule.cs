using System;
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

        public bool Equals(HashLimitModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Burst == other.Burst && string.Equals(Name, other.Name) && CompareRate(LimitMode, LimitRate, other.LimitRate) && Unit == other.Unit && LimitMode == other.LimitMode && string.Equals(Mode, other.Mode) && SrcMask == other.SrcMask && DstMask == other.DstMask && HtableSize == other.HtableSize && HtableMax == other.HtableMax && HtableExpire == other.HtableExpire && HtableGcInterval == other.HtableGcInterval;
        }

        public static UInt32 ComparablyReduce(UInt64 a)
        {
            if (a >= 5000)
            {
                a = 10000;
            }
            return (UInt32)(a / 10000);
        }

        public static bool CompareRate(HashLimitMode mode, UInt64 a, UInt64 b)
        {
            if ((mode & HashLimitMode.Bytes) == 0)
            {
                var a32 = ComparablyReduce(a);
                var b32 = ComparablyReduce(b);

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
            String ub = b.Substring(b.Length - 2, 1);


            UInt64 ret = 0;
            switch (ub)
            {
                case "g":
                case "G":
                    ret = UInt64.Parse(b.Substring(0, b.Length - 2)) * (1024 * 1024 * 1024);
                    if (scale == 'b') ub = "g";
                    break;
                case "m":
                case "M":
                    ret = UInt64.Parse(b.Substring(0, b.Length - 2)) * (1024 * 1024);
                    if (scale == 'b') ub = "m";
                    break;
                case "k":
                case "K":
                    ret = UInt64.Parse(b.Substring(0, b.Length - 2)) * 1024;
                    if (scale == 'b') ub = "k";
                    break;
                case "b":
                    ret = UInt64.Parse(b.Substring(0, b.Length - 1));
                    break;
                default:
                    ret = UInt64.Parse(b);
                    ub = "b";
                    break;
            }

            if (scale != ub.ToLower()[0])
            {
                switch (scale)
                {
                    case 'g':
                        ret = (ret / (1024 * 1024 * 1024)) * (1024 * 1024 * 1024);
                        break;
                    case 'm':
                        ret = (ret / (1024 * 1024)) * (1024 * 1024);
                        break;
                    case 'k':
                        ret = (ret / (1024)) * (1024);
                        break;
                }
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
                        LimitRate = ParseByte(s[0], ref _scale);
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
                    }
                    else
                    {
                        Burst = UInt64.Parse(parser.GetNextArg());
                    }

                    return 1;
            }

            return 0;
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
                OutputByte(sb, LimitRate);
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
            if (limitRate >= (1024 * 1024 * 1024))
            {
                sb.Append(limitRate / (1024 * 1024 * 1024));
                sb.Append("g");
            }
            else if (limitRate >= (1024 * 1024))
            {
                sb.Append(limitRate / (1024 * 1024));
                sb.Append("m");
            }
            else if (limitRate >= 1024)
            {
                sb.Append(limitRate / 1024);
                sb.Append("k");
            }
            else
            {
                sb.Append(limitRate);
            }
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