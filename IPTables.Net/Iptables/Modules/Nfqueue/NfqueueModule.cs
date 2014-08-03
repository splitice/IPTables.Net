using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Iptables.Helpers;

namespace IPTables.Net.Iptables.Modules.Nfqueue
{
    public class NfqueueModule : ModuleBase, IEquatable<NfqueueModule>, IIpTablesModuleGod
    {
        private const String OptionQueueNumber = "--queue-num";
        private const String OptionQueueBypass = "--queue-bypass";


        public int Num = 0;
        public bool Bypass = false;


        int IIpTablesModuleInternal.Feed(RuleParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionQueueNumber:
                    Num = int.Parse(parser.GetNextArg());
                    return 1;
                case OptionQueueBypass:
                    Bypass = int.Parse(parser.GetNextArg()) == 1;
                    return 1;
            }

            return 0;
        }

        public bool NeedsLoading
        {
            get { return false; }
        }

        public String GetRuleString()
        {
            var sb = new StringBuilder();

            if (Num != 0)
            {
                sb.Append(OptionQueueNumber + " ");
                sb.Append(Num);
            }

            if (Bypass)
            {
                if (sb.Length != 0) sb.Append(" ");
                sb.Append(OptionQueueBypass);
            }

            return sb.ToString();
        }

        public static IEnumerable<String> GetOptions()
        {
            var options = new List<string>
            {
                OptionQueueNumber,
                OptionQueueBypass
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetTargetModuleEntryInternal("NFQUEUE", typeof(NfqueueModule), GetOptions);
        }

        public bool Equals(NfqueueModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Num == other.Num && Bypass.Equals(other.Bypass);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != this.GetType()) return false;
            return Equals((NfqueueModule) obj);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                return (Num*397) ^ Bypass.GetHashCode();
            }
        }
    }
}