using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Mark
{
    public class MarkTargetModule : ModuleBase, IIpTablesModuleGod, IEquatable<MarkTargetModule>
    {
        //TODO: Proper mark implementation
        private const String OptionSetMarkLong = "--set-mark";
        private const String OptionSetXorMarkLong = "--set-xmark";

        public int? SetMark = null;

        public bool Equals(MarkTargetModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return SetMark.Equals(other.SetMark);
        }

        public bool NeedsLoading
        {
            get { return false; }
        }

        int IIpTablesModuleInternal.Feed(RuleParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionSetXorMarkLong:
                case OptionSetMarkLong:
                    string s = parser.GetNextArg();
                    int idxSlash = s.IndexOf('/');
                    if (idxSlash != -1)
                    {
                        s = s.Substring(0, idxSlash);
                    }
                    SetMark = FlexibleInt.Parse(s);
                    return 1;
            }

            return 0;
        }

        public String GetRuleString()
        {
            var sb = new StringBuilder();

            if (SetMark != null)
            {
                sb.Append(OptionSetMarkLong + " ");
                sb.Append(SetMark.Value);
            }

            return sb.ToString();
        }

        public static IEnumerable<String> GetOptions()
        {
            var options = new List<string>
            {
                OptionSetMarkLong,
                OptionSetXorMarkLong
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetTargetModuleEntryInternal("MARK", typeof (MarkTargetModule), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((MarkTargetModule) obj);
        }

        public override int GetHashCode()
        {
            return SetMark.GetHashCode();
        }
    }
}