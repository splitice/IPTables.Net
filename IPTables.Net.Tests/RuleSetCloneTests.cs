using System.Linq;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Modules.Comment;
using IPTables.Net.Iptables.Modules.Core;
namespace IPTables.Net.Tests;
public class RuleSetCloneTests
{
    [Theory]
    [InlineData(4)] [InlineData(6)]
    public void ClonePreservesCountersOrderingTablesAndOwnsAllMutableState(int version)
    {
        var system = new IpTablesSystem(new ScriptedSystem(), new RecordingAdapter());
        var source = new IpTablesRuleSet(version, system); source.AddChain("empty", "raw"); source.AddChain("custom", "filter");
        var address = version == 4 ? "192.0.2.1" : "2001:db8::1";
        string command = $"-A custom -s {address} -m comment --comment \"owner's rule\" -j ACCEPT";
        source.AddRule(command).Counters = new PacketCounters(900, 7);
        source.AddRule(command).Counters = new PacketCounters(1200, 9);
        source.AddRule("-A OUTPUT -t mangle -j RETURN").Counters = new PacketCounters(-1, -1);
        var clone = source.DeepClone();
        Assert.Equal(source, clone); Assert.Same(system, clone.System); Assert.Equal(version, clone.IpVersion);
        Assert.Empty(clone.Chains.GetChain("empty", "raw").Rules);
        var originals = source.Rules.ToArray(); var copies = clone.Rules.ToArray();
        Assert.Equal(3, copies.Length);
        for (int i = 0; i < copies.Length; i++)
        {
            Assert.Equal(originals[i].GetActionCommand(), copies[i].GetActionCommand());
            Assert.Equal(originals[i].Counters, copies[i].Counters); Assert.NotSame(originals[i], copies[i]);
            Assert.NotSame(originals[i].Chain, copies[i].Chain); Assert.Same(clone.Chains.GetChain(copies[i].Chain.Name, copies[i].Chain.Table), copies[i].Chain);
            Assert.Same(system, copies[i].System); Assert.Equal(version, copies[i].IpVersion);
            Assert.NotSame(originals[i].GetModule<CoreModule>("core"), copies[i].GetModule<CoreModule>("core"));
        }
        copies[0].GetModule<CommentModule>("comment").CommentText = "changed";
        copies[0].Counters = new PacketCounters(1, 2);
        var custom = clone.Chains.GetChain("custom", "filter"); custom.Rules.Reverse(); custom.Rules.RemoveAt(0);
        clone.AddRule("-A custom -j DROP"); clone.Chains.RemoveChain(clone.Chains.GetChain("empty", "raw"));
        Assert.Equal("owner's rule", originals[0].GetModule<CommentModule>("comment").CommentText);
        Assert.Equal(900, originals[0].Counters.Bytes); Assert.Equal(7, originals[0].Counters.Packets);
        Assert.Equal(originals, source.Rules.ToArray()); Assert.True(source.Chains.HasChain("empty", "raw")); Assert.NotEqual(source, clone);
    }
}
