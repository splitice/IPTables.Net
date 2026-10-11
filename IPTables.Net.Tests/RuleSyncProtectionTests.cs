using System;
using System.Collections.Generic;
using System.Linq;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Adapter;
using IPTables.Net.Iptables.Modules.Comment;
using IPTables.Net.Iptables.TableSync;
namespace IPTables.Net.Tests;
public class RuleSyncProtectionTests
{
    [Theory]
    [InlineData(0, false)] [InlineData(1, false)] [InlineData(2, false)]
    [InlineData(0, true)] [InlineData(1, true)] [InlineData(2, true)]
    public void ProtectedRulesSurviveChangesAndConverge(int position, bool restore)
    {
        var os = new ScriptedSystem();
        var system = new IpTablesSystem(os, restore ? new IPTablesRestoreAdapter() : new IPTablesBinaryAdapter());
        var commands = new List<string> { "-A INPUT -j ACCEPT", "-A INPUT -j RETURN" };
        commands.Insert(position, "-A INPUT -j DROP -m comment --comment protected");
        var current = new IpTablesRuleSet(4, commands, system).Chains.First();
        var desired = new IpTablesRuleSet(4, new[] { "-A INPUT -p tcp -j ACCEPT", "-A INPUT -p udp -j ACCEPT", "-A INPUT -j RETURN" }, system);
        var sync = new DefaultRuleSync(shouldDelete: r => r.GetModule<CommentModule>("comment")?.CommentText != "protected");
        using var client = system.GetTableAdapter(4);
        current.Sync(client, desired.Rules, sync);
        Assert.Single(current.Rules.Where(r => r.GetModule<CommentModule>("comment")?.CommentText == "protected"));
        Assert.Equal(desired.Rules.Select(r => r.GetActionCommand()), current.Rules.Where(sync.ShouldDelete).Select(r => r.GetActionCommand()));
        int before = os.Calls.Count; current.Sync(client, desired.Rules, sync); Assert.Equal(before, os.Calls.Count);
        current.Sync(client, Array.Empty<IpTablesRule>(), sync);
        Assert.Single(current.Rules);
    }
    [Fact]
    public void CustomEqualityCanIgnoreCommentsAndDuplicatesRemainOrdered()
    {
        var adapter = new RecordingAdapter(); var system = new IpTablesSystem(null, adapter);
        var current = new IpTablesRuleSet(4, new[] { "-A INPUT -j ACCEPT -m comment --comment one", "-A INPUT -j ACCEPT -m comment --comment two" }, system).Chains.First();
        var desired = new IpTablesRuleSet(4, new[] { "-A INPUT -j ACCEPT", "-A INPUT -j ACCEPT" }, system);
        new DefaultRuleSync(comparer: new IgnoreComment()).SyncChainRules(adapter, desired.Rules, current);
        Assert.Empty(adapter.Log); Assert.Equal(2, current.Rules.Count);
    }
    private sealed class IgnoreComment : IEqualityComparer<IpTablesRule>
    {
        public bool Equals(IpTablesRule x, IpTablesRule y) => x.GetActionCommand().Split(" -m comment")[0] == y.GetActionCommand().Split(" -m comment")[0];
        public int GetHashCode(IpTablesRule obj) => 0;
    }
}
