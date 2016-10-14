using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Ct
{
    public class CtTargetModule : ModuleBase, IIpTablesModule, IEquatable<CtTargetModule>
    {
        private const String OptionHelperLong = "--helper";
        private const String OptionCtEventsLong = "--ctevents";
        private const String OptionExpEventsLong = "--expevents";
        private const String OptionNotrack = "--notrack";

        public String Helper;
        public List<String> CtEvents = new List<string>();
        public List<String> ExpEvents = new List<string>(); 
        public bool NoTrack;

        public CtTargetModule(int version) : base(version)
        {
        }

        public bool Equals(CtTargetModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Helper == other.Helper && NoTrack == other.NoTrack && CtEvents.OrderBy((a) => a).SequenceEqual(other.CtEvents.OrderBy((a) => a)) && ExpEvents.OrderBy((a) => a).SequenceEqual(other.ExpEvents.OrderBy((a) => a));
        }

        public bool NeedsLoading
        {
            get { return false; }
        }

        public int Feed(RuleParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionNotrack:
                    NoTrack = true;
                    return 0;
                case OptionHelperLong:
                    Helper = parser.GetNextArg();
                    return 1;
                case OptionCtEventsLong:
                    CtEvents = parser.GetNextArg().Split(new char[]{','}).Select((a)=>a.Trim()).ToList();
                    return 1;
                case OptionExpEventsLong:
                    ExpEvents = parser.GetNextArg().Split(new char[] { ',' }).Select((a) => a.Trim()).ToList();
                    return 1;
            }

            return 0;
        }

        public String GetRuleString()
        {
            var sb = new StringBuilder();

            if (NoTrack)
            {
                sb.Append(OptionNotrack);
            }

            if (Helper != null)
            {
                sb.Append(OptionHelperLong + " ");
                sb.Append(Helper);
            }

            if (CtEvents.Any())
            {
                sb.Append(OptionCtEventsLong + " ");
                sb.Append(string.Join(",",CtEvents));
            }

            if (ExpEvents.Any())
            {
                sb.Append(OptionExpEventsLong + " ");
                sb.Append(string.Join(",", ExpEvents));
            }

            return sb.ToString();
        }

        public static HashSet<String> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionNotrack,
                OptionHelperLong,
                OptionCtEventsLong,
                OptionExpEventsLong
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetTargetModuleEntryInternal("CT", typeof(CtTargetModule), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((CtTargetModule)obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return Helper == null ? 0 : Helper.GetHashCode();
            }
        }
    }
}