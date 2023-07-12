using System;
using System.Diagnostics.CodeAnalysis;

namespace IPTables.Net.Iptables.Modules
{
    [DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicConstructors | DynamicallyAccessedMemberTypes.PublicMethods | DynamicallyAccessedMemberTypes.PublicProperties | DynamicallyAccessedMemberTypes.NonPublicFields | DynamicallyAccessedMemberTypes.PublicParameterlessConstructor)]
    public interface IIpTablesModule : ICloneable
    {
        bool NeedsLoading { get; }
        string GetRuleString();
        int Feed(CommandParser parser, bool not);
    }
}