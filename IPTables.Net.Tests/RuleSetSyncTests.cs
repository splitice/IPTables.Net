using System;
using System.Linq;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.TableSync;
namespace IPTables.Net.Tests;
public class RuleSetSyncTests
{
    [Theory]
    [InlineData("create filter/B")] [InlineData("add -A A -j B")] [InlineData("commit")]
    public void RetryRediscoversWithoutRetainingPendingChains(string failAt)
    {
        var adapter = new RecordingAdapter(); var system = new IpTablesSystem(null, adapter);
        var desired = new IpTablesRuleSet(4, new[] { "-A A -j B", "-A B -j ACCEPT", "-A X -t nat -j RETURN" }, system);
        bool failed = false;
        adapter.OnCall = call => { if (!failed && call == failAt) { failed = true; throw new IpTablesNetExceptionErrno("retry", 11); } };
        desired.Sync(new DefaultRuleSync(), maxRetries: 1);
        Assert.True(failed); Assert.Equal(2, adapter.Log.Count(x => x == "read filter"));
        Assert.Single(adapter.Log.Where(x => x == "rollback"));
        var retry = adapter.Log.Skip(adapter.Log.IndexOf("rollback") + 1).ToList();
        Assert.Single(retry.Where(x => x == "create filter/A"));
        Assert.True(retry.IndexOf("create filter/B") < retry.IndexOf("add -A A -j B"));
        Assert.Contains("create nat/X", retry);
    }
    [Theory]
    [InlineData(0, 11)] [InlineData(1, 11)] [InlineData(2, 5)]
    public void RetriesAreBoundedAndOriginalFailureSurvivesRollback(int retries, int errno)
    {
        var adapter = new RecordingAdapter(); var system = new IpTablesSystem(null, adapter);
        var failure = new IpTablesNetExceptionErrno("original", errno);
        adapter.OnCall = c => { if (c == "commit") throw failure; if (c == "rollback") throw new Exception("rollback"); };
        Assert.Same(failure, Assert.Throws<IpTablesNetExceptionErrno>(() => new IpTablesRuleSet(4, system).Sync(new DefaultRuleSync(), maxRetries: retries)));
        Assert.Equal(errno == 11 ? retries + 1 : 1, adapter.Log.Count(x => x == "commit"));
        Assert.Equal("dispose", adapter.Log.Last());
        Assert.Throws<ArgumentOutOfRangeException>(() => new IpTablesRuleSet(4, system).Sync(new DefaultRuleSync(), maxRetries: -1));
    }
    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)]
    public void ExistingRulesAndDeletionPolicy(int mode)
    {
        var adapter = new RecordingAdapter(); var system = new IpTablesSystem(null, adapter);
        var desired = new IpTablesRuleSet(4, new[] { "-A A -j ACCEPT" }, system);
        adapter.Read = _ => new IpTablesRuleSet(4, new[] { "-A A -j ACCEPT", "-A old -j RETURN", "-A foreign -j RETURN" }, system).Chains;
        Func<IpTablesChain, bool> delete = mode == 0 ? null : c => mode == 2 && c.Name == "old";
        desired.Sync(new DefaultRuleSync(), delete); desired.Sync(new DefaultRuleSync(), delete);
        Assert.DoesNotContain(adapter.Log, x => x.StartsWith("add ") || x.StartsWith("replace ") || x.Contains("delete filter/foreign"));
        Assert.Equal(mode == 2 ? 2 : 0, adapter.Log.Count(x => x == "delete filter/old"));
    }
}
