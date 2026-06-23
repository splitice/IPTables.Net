using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Modules.Core;
using IPTables.Net.Iptables.Modules.Dynjmp;

namespace IPTables.Net.Tests
{
    public class SingleDynjmpRuleParseTests
    {
        [Theory]
        [InlineData("-A INPUT -j DYNJMP")]
        [InlineData("-A INPUT -j SYNJMP")]
        public void TestNoOptionDynjmpTargetsRoundTrip(string rule)
        {
            RuleParseAssert.RoundTrips(rule);
        }

        [Theory]
        [InlineData("DYNJMP")]
        [InlineData("SYNJMP")]
        public void NoOptionJumpTargetsCompareWithGeneratedLoadedTargetRules(string target)
        {
            var parsed = IpTablesRule.Parse($"-A INPUT -j {target}", null, new IpTablesChainSet(4), 4);
            var generated = CreateGeneratedRule(target, jump: true, loadTarget: true);

            Assert.Equal(parsed.GetActionCommand(), generated.GetActionCommand());
            Assert.True(parsed.Compare(generated));
        }

        [Theory]
        [InlineData("DYNJMP")]
        [InlineData("SYNJMP")]
        public void NoOptionGotoTargetsCompareWithGeneratedCoreOnlyRules(string target)
        {
            var parsed = IpTablesRule.Parse($"-A INPUT -g {target}", null, new IpTablesChainSet(4), 4);
            var generated = CreateGeneratedRule(target, jump: false, loadTarget: false);

            Assert.Equal(parsed.GetActionCommand(), generated.GetActionCommand());
            Assert.True(parsed.Compare(generated));
        }

        private static IpTablesRule CreateGeneratedRule(string target, bool jump, bool loadTarget)
        {
            var chainSet = new IpTablesChainSet(4);
            var chain = chainSet.AddChain("INPUT", "filter", null);
            var generated = new IpTablesRule(null, chain);
            var core = generated.GetModuleOrLoad<CoreModule>("core");
            if (jump)
            {
                core.Jump = target;
            }
            else
            {
                core.Goto = target;
            }

            if (loadTarget)
            {
                if (target == "DYNJMP")
                {
                    generated.GetModuleOrLoad<DynjmpModule>("DYNJMP");
                }
                else
                {
                    generated.GetModuleOrLoad<SynjmpModule>("SYNJMP");
                }
            }

            return generated;
        }
    }
}
