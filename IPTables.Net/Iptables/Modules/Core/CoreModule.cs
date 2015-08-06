using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Core
{
    public class CoreModule : ModuleBase, IIpTablesModuleGod, IEquatable<CoreModule>
    {
        private const String OptionProtocolLong = "--protocol";
        private const String OptionProtocolShort = "-p";
        private const String OptionSourceLong = "--source";
        private const String OptionSourceShort = "-s";
        private const String OptionDestinationLong = "--destination";
        private const String OptionDestinationShort = "-d";
        private const String OptionJumpLong = "--jump";
        private const String OptionJumpShort = "-j";
        private const String OptionGotoLong = "--goto";
        private const String OptionGotoShort = "-g";
        private const String OptionInInterfaceLong = "--in-interface";
        private const String OptionInInterfaceShort = "-i";
        private const String OptionOutInterfaceLong = "--out-interface";
        private const String OptionOutInterfaceShort = "-o";
        private const String OptionFragmentLong = "--fragment";
        private const String OptionFragmentShort = "-f";
        private const String OptionSetCountersLong = "--set-counters";
        private const String OptionSetCountersShort = "-c";
        public ValueOrNot<IpCidr> Destination = new ValueOrNot<IpCidr>();
        public ValueOrNot<bool> Fragmented = new ValueOrNot<bool>();
        public ValueOrNot<String> InInterface = new ValueOrNot<String>();
        public ValueOrNot<String> OutInterface = new ValueOrNot<String>();

        public ValueOrNot<String> Protocol = new ValueOrNot<String>();
        public ValueOrNot<CounterPacketsAndBytes> SetCounters = new ValueOrNot<CounterPacketsAndBytes>();
        public ValueOrNot<IpCidr> Source = new ValueOrNot<IpCidr>();
        //Target
        public String Target = null;
        public TargetMode TargetMode = TargetMode.Jump;

        public CoreModule(int version) : base(version)
        {
        }

        public String Jump
        {
            get { return TargetMode == TargetMode.Jump ? Target : null; }
            set
            {
                if (value != null)
                {
                    TargetMode = TargetMode.Jump;
                    Target = value;
                }
            }
        }

        public String Goto
        {
            get { return TargetMode == TargetMode.Goto ? Target : null; }
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

        public bool NeedsLoading
        {
            get { return false; }
        }

        int IIpTablesModuleInternal.Feed(RuleParser parser, bool not)
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

        public String GetRuleString()
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
                if (Fragmented.Not)
                {
                    sb.Append("! ");
                }
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

        public static IEnumerable<String> GetOptions()
        {
            var options = new List<string>
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
            return GetModuleEntryInternal("core", typeof (CoreModule), GetOptions, true);
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