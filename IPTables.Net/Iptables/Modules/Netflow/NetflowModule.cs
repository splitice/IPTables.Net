using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using IPTables.Net.Iptables.DataTypes;
using IPTables.Net.Iptables.Modules.Dnat;

namespace IPTables.Net.Iptables.Modules.SynProxy
{
    public class NetflowModule : ModuleBase, IIpTablesModule, IEquatable<NetflowModule>
    {
        public NetflowModule(int version) : base(version)
        {
        }

        public bool Equals(NetflowModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return true;
        }

        public bool NeedsLoading
        {
            get { return false; }
        }

        public int Feed(RuleParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
            }

            return 0;
        }

        public String GetRuleString()
        {
            return "";
        }

        public static HashSet<String> GetOptions()
        {
            var options = new HashSet<string>
            {
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetTargetModuleEntryInternal("NETFLOW", typeof (NetflowModule), GetOptions, true);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((NetflowModule)obj);
        }
    }
}