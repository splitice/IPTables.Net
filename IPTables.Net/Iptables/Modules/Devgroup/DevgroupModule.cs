using System;
using System.Collections.Generic;
using IPTables.Net.Iptables.DataTypes;

namespace IPTables.Net.Iptables.Modules.Devgroup
{
    public class DevgroupModule : ModuleBase, IEquatable<DevgroupModule>, IIpTablesModule
    {
        private const String OptionSrcGroup = "--src-group";
        private const String OptionDstGroup = "--dst-group";

        public ValueOrNot<UInt32> SrcGroup { get; set; }
        public ValueOrNot<UInt32> DstGroup { get; set; }

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
                    SrcGroup = new ValueOrNot<UInt32>(FlexibleUInt32.Parse(parser.GetNextArg()), not);
                    return 1;
                case OptionDstGroup:
                    DstGroup = new ValueOrNot<UInt32>(FlexibleUInt32.Parse(parser.GetNextArg()), not);
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
            String ret = "";
            if (!SrcGroup.Null)
            {
                ret = SrcGroup.ToOption(OptionSrcGroup);
            }
            if (!DstGroup.Null)
            {
                if (ret != "") ret += " ";
                ret += DstGroup.ToOption(OptionDstGroup);
            }
            return ret;
        }

        public static HashSet<String> GetOptions()
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
            return GetModuleEntryInternal("devgroup", typeof (DevgroupModule), GetOptions);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(null, obj)) return false;
            if (ReferenceEquals(this, obj)) return true;
            if (obj.GetType() != GetType()) return false;
            return Equals((DevgroupModule)obj);
        }

        public override int GetHashCode()
        {
            return SrcGroup.GetHashCode() ^ DstGroup.GetHashCode();
        }
    }
}