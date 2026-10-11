using System;
using System.Linq;
using IPTables.Net.Exceptions;
using IPTables.Net.IpSet;
using IPTables.Net.IpSet.Adapter;
namespace IPTables.Net.Tests;
public class IpSetAdapterTests
{
    [Theory]
    [InlineData(0, "", true)] [InlineData(1, "", false)] [InlineData(2, "denied", false)]
    public void RestoreSuccessMeansZeroExitAndIncludesFullCommands(int exit, string error, bool success)
    {
        var os = new ScriptedSystem { Respond = (_, _) => new("", error, exit) };
        var adapter = new IpSetBinaryAdapter(os);
        var sets = new IpSetSets(new[] { "create demo hash:ip", "add demo 192.0.2.1 timeout 12" }, null);
        if (error.Length == 0) Assert.Equal(success, adapter.RestoreSets(sets.Sets));
        else Assert.Throws<IpTablesNetException>(() => adapter.RestoreSets(sets.Sets));
        var call = Assert.Single(os.Calls);
        Assert.StartsWith("create demo hash:ip", call.Text);
        Assert.Contains("add demo 192.0.2.1 timeout 12", call.Text);
        Assert.False(call.Input.CanWrite); Assert.True(call.Process.IsDisposed);
    }
    [Fact]
    public void TransactionLifecycleAndFailureRecovery()
    {
        var os = new ScriptedSystem(); var adapter = new IpSetBinaryAdapter(os);
        adapter.StartTransaction(); Assert.Throws<IpTablesNetException>(() => adapter.StartTransaction());
        Assert.True(adapter.EndTransactionCommit()); Assert.Empty(os.Calls);
        adapter.StartTransaction(); adapter.DestroySet("old"); adapter.EndTransactionRollback();
        adapter.StartTransaction(); adapter.DestroySet("new"); adapter.EndTransactionCommit();
        Assert.Equal("destroy new\n", os.Calls.Last().Text.Replace("\r", ""));
        os.Respond = (_, _) => new("", "failure", 1);
        adapter.StartTransaction(); adapter.DestroySet("bad");
        Assert.Throws<IpTablesNetException>(() => adapter.EndTransactionCommit()); Assert.False(adapter.InTransaction);
        os.Respond = (_, _) => new();
        adapter.StartTransaction(); adapter.DestroySet("last"); adapter.EndTransactionCommit();
        Assert.DoesNotContain("bad", os.Calls.Last().Text);
    }
    [Fact]
    public void ImmediateFailuresAndFailedSavesAreReported()
    {
        var os = new ScriptedSystem { Respond = (_, _) => new("create partial hash:ip", "failure", 1) };
        var adapter = new IpSetBinaryAdapter(os);
        var set = new IpSetSets(new[] { "create demo hash:ip", "add demo 192.0.2.1" }, null).Sets.Single();
        foreach (Action call in new Action[] { () => adapter.CreateSet(set), () => adapter.DestroySet("demo"),
            () => adapter.AddEntry(set.Entries.Single()), () => adapter.DeleteEntry(set.Entries.Single()), () => adapter.SwapSet("a", "b") })
            Assert.Throws<IpTablesNetException>(call);
        var target = new IpSetSets(null); Assert.Throws<IpTablesNetException>(() => adapter.SaveSets(target)); Assert.Empty(target.Sets);
        Assert.All(os.Calls, c => Assert.True(c.Process.IsDisposed));
    }
}
