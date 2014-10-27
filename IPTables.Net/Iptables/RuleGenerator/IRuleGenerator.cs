namespace IPTables.Net.Iptables.RuleGenerator
{
    interface IRuleGenerator
    {
        void AddRule(IpTablesRule rule);
        void Output(IpTablesSystem system, IpTablesRuleSet ruleSet);
    }
}
