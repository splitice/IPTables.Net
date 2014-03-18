using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Common;

namespace IPTables.Net.Iptables.Modules.Nfacct
{
    public class NfacctModule : ModuleBase, IEquatable<NfacctModule>, IIpTablesModuleGod
    {
        private const String OptionNameLong = "--nfacct-name";

        public String Name;

        public bool Equals(NfacctModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return string.Equals(Name, other.Name);
        }

        int IIpTablesModuleInternal.Feed(RuleParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionNameLong:
                    Name = parser.GetNextArg();
                    return 1;
            }

            return 0;
        }

        public bool NeedsLoading
        {
            get { return true; }
        }

        public String GetRuleString()
        {
            var sb = new StringBuilder();

            if (!String.IsNullOrEmpty(Name))
            {
                sb.Append("--nfacct-name ");
                sb.Append(Helpers.EscapeArguments(Name));
            }

            return sb.ToString();
        }

        public static IEnumerable<String> GetOptions()
        {
            var options = new List<string>
            {
                OptionNameLong
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("nfacct", typeof (NfacctModule), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((NfacctModule) obj);
        }

        public override int GetHashCode()
        {
            return (Name != null ? Name.GetHashCode() : 0);
        }
    }
}