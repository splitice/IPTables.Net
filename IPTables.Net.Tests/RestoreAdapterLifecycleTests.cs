using System;
using System.Linq;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Adapter;
namespace IPTables.Net.Tests;
public class RestoreAdapterLifecycleTests
{
    [Fact]
    public void CommitRollbackAndFailureDoNotReplayOldCommands()
    {
        var os = new ScriptedSystem();
        using var client = new IpTablesSystem(os, new IPTablesRestoreAdapter()).GetTableAdapter(4);
        client.EndTransactionCommit(); client.EndTransactionRollback();
        client.StartTransaction(); client.EndTransactionCommit();
        Assert.Empty(os.Calls);
        client.StartTransaction(); client.AddRule("-A INPUT -j ACCEPT"); client.EndTransactionCommit();
        client.StartTransaction(); client.AddRule("-A INPUT -j DROP"); client.EndTransactionRollback();
        client.StartTransaction(); client.AddRule("-A OUTPUT -j RETURN"); client.EndTransactionCommit();
        Assert.DoesNotContain("INPUT", os.Calls[1].Text);
        os.Respond = (_, _) => new("", "denied", 1);
        client.StartTransaction(); client.AddRule("-A INPUT -j DROP");
        Assert.Throws<IpTablesNetException>(() => client.EndTransactionCommit());
        client.EndTransactionRollback();
        os.Respond = (_, _) => new();
        client.StartTransaction(); client.AddRule("-A OUTPUT -j ACCEPT"); client.EndTransactionCommit();
        Assert.DoesNotContain("DROP", os.Calls.Last().Text);
    }
    [Fact]
    public void NestedStartAndActiveDisposeRequireExplicitResolution()
    {
        using var client = new IpTablesSystem(new ScriptedSystem(), new IPTablesRestoreAdapter()).GetTableAdapter(4);
        client.StartTransaction();
        Assert.Throws<IpTablesNetException>(() => client.StartTransaction());
        Assert.Throws<IpTablesNetException>(() => client.Dispose());
        client.EndTransactionRollback();
    }
    [Fact]
    public void ImmediateOperationsNeverLeakIntoNextTransaction()
    {
        var os = new ScriptedSystem();
        var system = new IpTablesSystem(os, new IPTablesRestoreAdapter());
        using var client = system.GetTableAdapter(6);
        var rule = IpTablesRule.Parse("-A INPUT -j ACCEPT", system, new IpTablesChainSet(6), 6);
        rule.Chain.AddRule(rule);
        client.AddRule(rule); client.AddRule("-A INPUT -j DROP"); client.InsertRule(rule);
        client.ReplaceRule(rule); client.DeleteRule(rule); client.DeleteRule("filter", "INPUT", 1);
        client.AddChain("filter", "custom"); client.DeleteChain("filter", "custom", true);
        Assert.All(os.Calls, c => Assert.Equal("ip6tables", c.Binary));
        Assert.Equal(new[] { "-t filter -F custom", "-t filter -X custom" }, os.Calls.TakeLast(2).Select(c => c.Arguments));
        client.StartTransaction(); client.AddRule("-A OUTPUT -j RETURN"); client.EndTransactionCommit();
        Assert.Equal("*filter\n-A OUTPUT -j RETURN\nCOMMIT\n\n", os.Calls.Last().Text.Replace("\r", ""));
        Assert.Equal("ip6tables-restore", os.Calls.Last().Binary);
    }
}
