using System;
using System.Collections.Generic;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Devgroup
{
    public class DevgroupModule : ModuleBase, IEquatable<DevgroupModule>, IIpTablesModule
    {
        private const string OptionSrcGroup = "--src-group";
        private const string OptionDstGroup = "--dst-group";

        public ValueOrNot<uint> SrcGroup { get; set; }
        public ValueOrNot<uint> DstGroup { get; set; }

        public DevgroupModule(int version) : base(version)
        {
        }

        public bool Equals(DevgroupModule other)
        {
            if (ReferenceEquals(null, other)) return false;
            if (ReferenceEquals(this, other)) return true;
            return SrcGroup.Equals(other.SrcGroup) && DstGroup.Equals(other.DstGroup);
        }

        public int Feed(CommandParser parser, bool not)
        {
            switch (parser.GetCurrentArg())
            {
                case OptionSrcGroup:
                    SrcGroup = new ValueOrNot<uint>(FlexibleUInt32.Parse(parser.GetNextArg()), not);
                    return 1;
                case OptionDstGroup:
                    DstGroup = new ValueOrNot<uint>(FlexibleUInt32.Parse(parser.GetNextArg()), not);
                    return 1;
            }

            return 0;
        }

        public bool NeedsLoading => true;

        public string GetRuleString()
        {
            var ret = "";
            if (!SrcGroup.Null) ret = SrcGroup.ToOption(OptionSrcGroup);
            if (!DstGroup.Null)
            {
                if (ret != "") ret += " ";
                ret += DstGroup.ToOption(OptionDstGroup);
            }

            return ret;
        }

        public static HashSet<string> GetOptions()
        {
            var options = new HashSet<string>
            {
                OptionSrcGroup,
                OptionDstGroup
            };
            return options;
        }

        public static ModuleEntry GetModuleEntry()
        {
            return GetModuleEntryInternal("devgroup", typeof(DevgroupModule), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((DevgroupModule) obj);
        }

        public override int GetHashCode()
        {
            return SrcGroup.GetHashCode() ^ DstGroup.GetHashCode();
        }
    }
}