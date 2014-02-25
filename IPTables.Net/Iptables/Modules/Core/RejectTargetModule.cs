using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace IPTables.Net.Iptables.Modules.Core
{
    internal class RejectTargetModule : ModuleBase, IIpTablesModuleGod, IEquatable<RejectTargetModule>
    {
        private const String OptionRejectWith = "--reject-with";

        public String RejectWith = "";

        public bool NeedsLoading
        {
            get
            {
                return false;
            }
        }

        int IIpTablesModuleInternal.Feed(RuleParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionRejectWith:
                    RejectWith = parser.GetNextArg();
                    return 1;
            }

            return 0;
        }

        public String GetRuleString()
        {
            var sb = new StringBuilder();

            if (!String.IsNullOrEmpty(RejectWith))
            {
                if (sb.Length != 0)
                    sb.Append(" ");
                sb.Append(OptionRejectWith + " ");
                sb.Append(RejectWith);
            }

            return sb.ToString();
        }

        public static IEnumerable<String> GetOptions()
        {
            var options = new List<string>
                          {
                              OptionRejectWith
                          };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetTargetModuleEntryInternal("REJECT", typeof (RejectTargetModule), GetOptions, true);
        }

        public bool Equals(RejectTargetModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return string.Equals(RejectWith, other.RejectWith);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((RejectTargetModule) obj);
        }

        public override int GetHashCode()
        {
            return (RejectWith != null ? RejectWith.GetHashCode() : 0);
        }
    }
}
