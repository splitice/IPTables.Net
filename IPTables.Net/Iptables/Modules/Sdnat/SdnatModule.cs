using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Sdnat
{
    public class SdnatModule : ModuleBase, IIpTablesModule, IEquatable<SdnatModule>
    {
        private const String OptionToSource = "--to-source";
        private const String OptionToDestination = "--to-destination";
        private const String OptionRandom = "--random";
        private const String OptionPersisent = "--persistent";
        private const String OptionCtMask = "--ctmask";
        private const String OptionCtMark = "--ctmark";
        private const String OptionSeqadj = "--also-seqadj";

        public bool Persistent = false;
        public bool Random = false;
        public bool Seqadj = false;
        public IPPortOrRange ToSource = new IPPortOrRange(IPAddress.Any);
        public IPPortOrRange ToDestination = new IPPortOrRange(IPAddress.Any);
        public UInt32 CtMark;
        public UInt32 CtMask;

        public SdnatModule(int version) : base(version)
        {
        }

        public bool Equals(SdnatModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Persistent.Equals(other.Persistent) && Random.Equals(other.Random) && ToSource.Equals(other.ToSource) && ToDestination.Equals(other.ToDestination) && CtMark == other.CtMark && CtMask == other.CtMask && Seqadj == other.Seqadj;
        }

        public bool NeedsLoading
        {
            get { return false; }
        }

        public int Feed(CommandParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionToSource:
                    ToSource = IPPortOrRange.Parse(parser.GetNextArg());
                    return 1;

                case OptionToDestination:
                    ToDestination = IPPortOrRange.Parse(parser.GetNextArg());
                    return 1;
                    
                case OptionRandom:
                    Random = true;
                    return 0;

                case OptionPersisent:
                    Persistent = true;
                    return 0;

                case OptionSeqadj:
                    Seqadj = true;
                    return 0;

                case OptionCtMark:
                    CtMark = FlexibleUInt32.Parse(parser.GetNextArg());
                    return 1;

                case OptionCtMask:
                    CtMask = FlexibleUInt32.Parse(parser.GetNextArg());
                    return 1;
            }

            return 0;
        }

        public String GetRuleString()
        {
            var sb = new StringBuilder();

            if (!Equals(ToSource.LowerAddress, IPAddress.Any))
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(OptionToSource + " ");
                sb.Append(ToSource);
            }

            if (!Equals(ToDestination.LowerAddress, IPAddress.Any))
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(OptionToDestination + " ");
                sb.Append(ToDestination);
            }

            if (Random)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(OptionRandom);
            }

            if (Seqadj)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(OptionSeqadj);
            }

            if (Persistent)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(OptionPersisent);
            }
            
            if (CtMark != 0)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(OptionCtMark + " " + CtMark);
            }

            if (CtMask != 0)
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(OptionCtMask + " " + CtMask);
            }

            return sb.ToString();
        }

        public static HashSet<String> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionToSource,
                OptionToDestination,
                OptionRandom,
                OptionPersisent,
                OptionCtMask,
                OptionCtMark,
                OptionSeqadj
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetTargetModuleEntryInternal("SDNAT", typeof (SdnatModule), GetOptions, false);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((SdnatModule) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                int hashCode = Persistent.GetHashCode();
                hashCode = (hashCode*397) ^ Random.GetHashCode();
                hashCode = (hashCode*397) ^ ToSource.GetHashCode();
                hashCode = (hashCode * 397) ^ ToDestination.GetHashCode();
                hashCode = (hashCode * 397) ^ CtMask.GetHashCode();
                hashCode = (hashCode * 397) ^ CtMark.GetHashCode();
                return hashCode;
            }
        }
    }
}