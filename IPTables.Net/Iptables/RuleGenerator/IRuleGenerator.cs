namespace IPTables.Net.Iptables.RuleGenerator
{
    public interface IRuleGenerator
    {
        void AddRule(IpTablesRule rule);
        void Output(IpTablesSystem system, IpTablesRuleSet ruleSet);
    }
}