using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Iptables.DataTypes;
using IPTables.Net.Iptables.Helpers;
using IPTables.Net.Iptables.Modules.Log;

namespace IPTables.Net.Iptables.Modules.Statistic
{
    public class StatisticModule : ModuleBase, IEquatable<StatisticModule>, IIpTablesModule
    {
        private const String OptionModeLong = "--mode";
        private const String OptionProbabilityLong = "--probability";
        private const String OptionEveryLong = "--every";
        private const String OptionPacketLong = "--packet";

        public enum Modes
        {
            Random, Nth
        }

        public Modes Mode;
        public ValueOrNot<uint> Every;
        public uint Packet;

        public double Probability
        {
            get { return Every.Value/2147483648.0; }
            set { Every = new ValueOrNot<uint>((uint)(value * 2147483648), Every.Not); }
        }

        public StatisticModule(int version)
            : base(version)
        {
        }

        public int Feed(RuleParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionModeLong:
                    Mode = ParseMode(parser.GetNextArg());
                    return 1;
                case OptionProbabilityLong:
                    Every = new ValueOrNot<uint>(0, not);
                    Probability = double.Parse(parser.GetNextArg());
                    return 1;
                case OptionPacketLong:
                    Packet = uint.Parse(parser.GetNextArg());
                    return 1;
                case OptionEveryLong:
                    Every = new ValueOrNot<uint>(uint.Parse(parser.GetNextArg()), not);
                    return 1;
            }

            return 0;
        }

        public static Modes ParseMode(string mode)
        {
            switch (mode)
            {
                case "random":
                    return Modes.Random;
                case "nth":
                    return Modes.Nth;
                default:
                    throw new ArgumentException("Invalid argument: "+mode);
            }
        }

        public static string OutputMode(Modes mode)
        {
            switch (mode)
            {
                case Modes.Random:
                    return "random";
                case Modes.Nth:
                    return "nth";
                default:
                    throw new ArgumentException("Invalid argument: " + mode);
            }
        }

        public bool NeedsLoading
        {
            get { return true; }
        }

        public String GetRuleString()
        {
            var sb = new StringBuilder();

            sb.Append(OptionModeLong + " " + OutputMode(Mode) + " ");

            switch (Mode)
            {
                case Modes.Nth:
                    sb.Append(OptionEveryLong + " " + Every + " " + OptionPacketLong + " " + Packet);
                    break;
                case Modes.Random:
                    sb.Append(OptionProbabilityLong + " " + Probability);
                    break;
            }

            return sb.ToString();
        }

        public static HashSet<String> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionModeLong,
                OptionEveryLong,
                OptionPacketLong,
                OptionProbabilityLong
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("statistic", typeof (StatisticModule), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((StatisticModule) obj);
        }

        public bool Equals(StatisticModule other)
        {
            return Mode == other.Mode && Every.Equals(other.Every) && Packet == other.Packet;
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = (int) Mode;
                hashCode = (hashCode*397) ^ Every.GetHashCode();
                hashCode = (hashCode*397) ^ (int) Packet;
                return hashCode;
            }
        }
    }
}