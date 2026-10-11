using System;
using System.Collections.Generic;
using System.Linq;
using IPTables.Net.Exceptions;
using IPTables.Net.IpSet;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.DataTypes;
using IPTables.Net.Iptables.Helpers;
using IPTables.Net.Iptables.Modules.Core;
using IPTables.Net.Iptables.Modules.Tcp;
using IPTables.Net.Iptables.Modules.Udp;
using IPTables.Net.Iptables.RuleGenerator;
namespace IPTables.Net.Tests;
public class RuleGeneratorBoundaryTests
{
    [Theory]
    [InlineData(14, false, false, false)] [InlineData(15, true, false, false)]
    [InlineData(16, false, true, false)] [InlineData(14, true, true, true)]
    public void SlotLimitsPreservePortsTargetsAndBaseMatches(int count, bool tcp, bool source, bool range)
    {
        var system = new IpTablesSystem(new ScriptedSystem(), new RecordingAdapter());
        var rules = new IpTablesRuleSet(4, system); rules.AddChain("TARGET", "mangle");
        var inputs = Enumerable.Range(1, count).Select(x => new PortOrRange((uint)x * 10)).ToList();
        if (range) inputs.Add(new PortOrRange(200, 210));
        var batches = new List<List<PortOrRange>>(); var protocol = tcp ? "tcp" : "udp";
        var gen = new MultiportAggregator<string>("INPUT", "mangle", _ => "group",
            rule => tcp ? (source ? rule.GetModule<TcpModule>("tcp").SourcePort.Value : rule.GetModule<TcpModule>("tcp").DestinationPort.Value) :
                (source ? rule.GetModule<UdpModule>("udp").SourcePort.Value : rule.GetModule<UdpModule>("udp").DestinationPort.Value),
            (rule, ports) => { batches.Add(ports); if (source) PortRangeHelpers.SourcePortSetter(rule, ports); else PortRangeHelpers.DestinationPortSetter(rule, ports); },
            null, "gap", "-A INPUT -t mangle -i eth0");
        foreach (var port in inputs) gen.AddRule(IpTablesRule.Parse($"-A INPUT -t mangle -p {protocol} -m {protocol} --{(source ? "sport" : "dport")} {port} -g TARGET", system, rules.Chains));
        gen.Output(system, rules);
        Assert.Equal(count == 16 || range ? 2 : 1, batches.Count);
        Assert.All(batches, ports => Assert.InRange(ports.Sum(p => p.IsRange() ? 2 : 1), 1, 15));
        static IEnumerable<uint> Expand(IEnumerable<PortOrRange> ports) => ports.SelectMany(p => Enumerable.Range((int)p.LowerPort, (int)(p.UpperPort - p.LowerPort + 1)).Select(x => (uint)x));
        Assert.Equal(Expand(inputs).Order(), Expand(batches.SelectMany(x => x)).Order());
        foreach (var rule in rules.Rules)
        {
            var core = rule.GetModule<CoreModule>("core"); Assert.Equal("eth0", core.InInterface.Value);
            var target = core.TargetMode == TargetMode.Goto ? core.Goto : core.Jump;
            Assert.True(rules.Chains.HasChain(target, "mangle"));
            if (target == "TARGET") { Assert.Equal(TargetMode.Goto, core.TargetMode); Assert.Equal(protocol, core.Protocol.Value); }
        }
        Assert.Throws<IpTablesNetException>(() => gen.Output(system, rules));
    }
    [Fact]
    public void CompressionUnionsOverlapDuplicatesZeroAndUnsignedMaximum()
    {
        var compressed = PortRangeHelpers.CompressRanges(new() { new(0, 3), new(2, 5), new(5), new(6), new(uint.MaxValue) });
        Assert.Equal(new[] { new PortOrRange(0, 6), new PortOrRange(uint.MaxValue) }, compressed);
    }
    [Fact]
    public void IpSetModeEmitsOneSetContainingEveryPort()
    {
        var system = new IpTablesSystem(new ScriptedSystem(), new RecordingAdapter()); var rules = new IpTablesRuleSet(4, system); var sets = new IpSetSets(system);
        var gen = new MultiportAggregator<string>("INPUT", "filter", _ => "a", r => r.GetModule<UdpModule>("udp").DestinationPort.Value,
            (r, ports) => PortRangeHelpers.DestinationPortIpSetter(r, ports, "ports", sets), null, "gap", ipset: true);
        for (int i = 1; i <= 16; i++) gen.AddRule(IpTablesRule.Parse($"-A INPUT -p udp -m udp --dport {i * 10} -j ACCEPT", system, rules.Chains));
        gen.Output(system, rules);
        Assert.Equal(Enumerable.Range(1, 16).Select(x => (ushort)(x * 10)), Assert.Single(sets.Sets).Entries.Select(x => (ushort)x.Port).Order());
        Assert.Single(rules.Rules.Where(x => x.GetCommand().Contains("--match-set ports dst")));
    }
    [Fact]
    public void EmptyGroupsAndNestedGeneratorsLeaveNoDanglingJumps()
    {
        var system = new IpTablesSystem(new ScriptedSystem(), new RecordingAdapter()); var rules = new IpTablesRuleSet(4, system);
        var gen = new MultiportAggregator<string>("INPUT", "filter", null, _ => new(80), (_, _) => { }, null, "gap");
        gen.Rules.Add("empty", new()); gen.Output(system, rules); Assert.Empty(rules.Chains);
        var rule = IpTablesRule.Parse("-A INPUT -j ACCEPT", system, new IpTablesChainSet(4));
        Assert.Throws<IpTablesNetException>(() => gen.AddRule(rule));
        gen.AddRule(rule, "explicit"); gen.Output(system, rules); Assert.Single(rules.Rules);
        var split = new FeatureSplitter<Empty>("INPUT", "filter", _ => "key", (_, _) => { }, (_, _) => new Empty(), "gap");
        rules = new IpTablesRuleSet(4, system); split.AddRule(rule); split.Output(system, rules); Assert.Empty(rules.Rules);
        Assert.All(rules.Chains, chain => Assert.Equal("INPUT", chain.Name));
        Assert.Throws<ArgumentNullException>(() => new MultiportAggregator<string>("INPUT", "filter", null, null, (_, _) => { }, null, "gap"));
        Assert.Throws<ArgumentNullException>(() => new FeatureSplitter<Empty>("INPUT", "filter", null, (_, _) => { }, (_, _) => new Empty(), "gap"));
    }
    private sealed class Empty : IRuleGenerator { public void AddRule(IpTablesRule rule) { } public void Output(IpTablesSystem system, IpTablesRuleSet rules) { } }
}
