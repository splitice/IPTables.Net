namespace IPTables.Net.Iptables.Modules
{
    internal interface IIpTablesModuleInternal
    {
        int Feed(RuleParser parser, bool not);
    }
}