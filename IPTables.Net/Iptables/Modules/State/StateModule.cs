using System;
using System.Collections.Generic;
using System.Text;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.State
{
    public class StateModule : ModuleBase, IIpTablesModuleGod, IEquatable<StateModule>
    {
        private const String OptionState = "--state";

        public ConnectionStateSet State = null;

        public StateModule(int version) : base(version)
        {
        }

        public bool Equals(StateModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return Equals(State, other.State);
        }

        public bool NeedsLoading
        {
            get { return true; }
        }

        int IIpTablesModuleInternal.Feed(RuleParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionState:
                    State = ConnectionStateSet.Parse(parser.GetNextArg());
                    return 1;
            }

            return 0;
        }

        public String GetRuleString()
        {
            var sb = new StringBuilder();

            if (State != null)
            {
                sb.Append(OptionState + " ");
                sb.Append(State);
            }

            return sb.ToString();
        }

        public static IEnumerable<String> GetOptions()
        {
            var options = new List<string>
            {
                OptionState
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("state", typeof (StateModule), GetOptions, true);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((StateModule) obj);
        }

        public override int GetHashCode()
        {
            return (State != null ? State.GetHashCode() : 0);
        }
    }
}