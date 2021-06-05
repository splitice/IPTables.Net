using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Core
{
    public class CoreModule : ModuleBase, IIpTablesModule, IEquatable<CoreModule>
    {
        private const string OptionProtocolLong = "--protocol";
        private const string OptionProtocolShort = "-p";
        private const string OptionSourceLong = "--source";
        private const string OptionSourceShort = "-s";
        private const string OptionDestinationLong = "--destination";
        private const string OptionDestinationShort = "-d";
        private const string OptionJumpLong = "--jump";
        private const string OptionJumpShort = "-j";
        private const string OptionGotoLong = "--goto";
        private const string OptionGotoShort = "-g";
        private const string OptionInInterfaceLong = "--in-interface";
        private const string OptionInInterfaceShort = "-i";
        private const string OptionOutInterfaceLong = "--out-interface";
        private const string OptionOutInterfaceShort = "-o";
        private const string OptionFragmentLong = "--fragment";
        private const string OptionFragmentShort = "-f";
        private const string OptionSetCountersLong = "--set-counters";
        private const string OptionSetCountersShort = "-c";
        public ValueOrNot<IpCidr> Destination { get; set; } = new ValueOrNot<IpCidr>();
        public ValueOrNot<bool> Fragmented { get; set; } = new ValueOrNot<bool>();
        public ValueOrNot<string> InInterface { get; set; } = new ValueOrNot<string>();
        public ValueOrNot<string> OutInterface { get; set; } = new ValueOrNot<string>();

        public ValueOrNot<string> Protocol { get; set; } = new ValueOrNot<string>();
        public ValueOrNot<CounterPacketsAndBytes> SetCounters { get; set; } = new ValueOrNot<CounterPacketsAndBytes>();

        public ValueOrNot<IpCidr> Source { get; set; } = new ValueOrNot<IpCidr>();

        //Target
        public string Target { get; set; } = null;
        public TargetMode TargetMode { get; set; } = TargetMode.Jump;

        public CoreModule(int version) : base(version)
        {
        }

        public string Jump
        {
            get => TargetMode == TargetMode.Jump ? Target : null;
            set
            {
                if (value != null)
                {
                    TargetMode = TargetMode.Jump;
                    Target = value;
                }
            }
        }

        public string Goto
        {
            get => TargetMode == TargetMode.Goto ? Target : null;
            set
            {
                if (value != null)
                {
                    TargetMode = TargetMode.Goto;
                    Target = value;
                }
            }
        }

        public bool Equals(CoreModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Destination.Equals(other.Destination) && Fragmented.Equals(other.Fragmented) &&
                   InInterface.Equals(other.InInterface) && OutInterface.Equals(other.OutInterface) &&
                   Protocol.Equals(other.Protocol) && SetCounters.Equals(other.SetCounters) &&
                   Source.Equals(other.Source) && string.Equals(Target, other.Target) && TargetMode == other.TargetMode;
        }

        public bool NeedsLoading => false;

        public int Feed(CommandParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionProtocolLong:
                case OptionProtocolShort:
                    Protocol = new ValueOrNot<string>(parser.GetNextArg(), not);
                    return 1;
                case OptionSourceLong:
                case OptionSourceShort:
                    Source = new ValueOrNot<IpCidr>(IpCidr.Parse(parser.GetNextArg()), IpCidr.Any, not);
                    return 1;
                case OptionDestinationLong:
                case OptionDestinationShort:
                    Destination = new ValueOrNot<IpCidr>(IpCidr.Parse(parser.GetNextArg()), IpCidr.Any, not);
                    return 1;
                case OptionJumpLong:
                case OptionJumpShort:
                    Jump = parser.GetNextArg();
                    return 1;
                case OptionGotoLong:
                case OptionGotoShort:
                    Goto = parser.GetNextArg();
                    return 1;
                case OptionInInterfaceLong:
                case OptionInInterfaceShort:
                    InInterface = new ValueOrNot<string>(parser.GetNextArg(), not);
                    return 1;
                case OptionOutInterfaceLong:
                case OptionOutInterfaceShort:
                    OutInterface = new ValueOrNot<string>(parser.GetNextArg(), not);
                    return 1;
                case OptionFragmentLong:
                case OptionFragmentShort:
                    Fragmented = new ValueOrNot<bool>(true, not);
                    return 0;
                case OptionSetCountersLong:
                case OptionSetCountersShort:
                    SetCounters =
                        new ValueOrNot<CounterPacketsAndBytes>(
                            new CounterPacketsAndBytes(uint.Parse(parser.GetNextArg(1)),
                                uint.Parse(parser.GetNextArg(2))), not);
                    return 2;
            }

            return 0;
        }

        public string GetRuleString()
        {
            var sb = new StringBuilder();

            if (!Protocol.Null)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(Protocol.ToOption(OptionProtocolShort));
            }

            if (!Source.Null)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(Source.ToOption(OptionSourceShort));
            }

            if (!Destination.Null)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(Destination.ToOption(OptionDestinationShort));
            }

            if (!InInterface.Null)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(InInterface.ToOption(OptionInInterfaceShort));
            }

            if (!OutInterface.Null)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(OutInterface.ToOption(OptionOutInterfaceShort));
            }

            if (!Fragmented.Null)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                if (Fragmented.Not) sb.Append("! ");
                sb.Append("-f");
            }

            sb.Append(SetCounters.ToOption(OptionFragmentShort));

            if (Target != null)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                if (TargetMode == TargetMode.Jump)
                {
                    sb.Append("-j ");
                    sb.Append(Target);
                }
                else if (TargetMode == TargetMode.Goto)
                {
                    sb.Append("-g ");
                    sb.Append(Target);
                }
            }

            return sb.ToString();
        }

        public static HashSet<string> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionProtocolLong,
                OptionProtocolShort,
                OptionSourceLong,
                OptionSourceShort,
                OptionDestinationLong,
                OptionDestinationShort,
                OptionJumpLong,
                OptionJumpShort,
                OptionGotoLong,
                OptionGotoShort,
                OptionInInterfaceLong,
                OptionInInterfaceShort,
                OptionOutInterfaceLong,
                OptionOutInterfaceShort,
                OptionFragmentLong,
                OptionFragmentShort,
                OptionSetCountersLong,
                OptionSetCountersShort
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("core", typeof(CoreModule), GetOptions, true);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((CoreModule) obj);
        }
    }
}