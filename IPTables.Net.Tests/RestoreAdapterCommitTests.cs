using System;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.Adapter;

namespace IPTables.Net.Tests;
public class RestoreAdapterCommitTests
{
    [Theory]
    [InlineData(0, "")] [InlineData(1, "line 2 failed")] [InlineData(1, "line 1 failed")]
    [InlineData(1, "line 999 failed")] [InlineData(1, "general failure")]
    [InlineData(2, "invalid option")] [InlineData(9, "unknown failure")]
    public void ProductionCommitReportsExitAndInput(int exit, string error)
    {
        var os = new ScriptedSystem { Respond = (_, _) => new("", error, exit) };
        var system = new IpTablesSystem(os, new IPTablesRestoreAdapter());
        using var client = system.GetTableAdapter(4);
        client.StartTransaction();
        client.AddRule("-A INPUT -j ACCEPT");
        try
        {
            if (exit == 0) client.EndTransactionCommit();
            else
            {
                var ex = Assert.Throws<IpTablesNetException>(() => client.EndTransactionCommit());
                Assert.Contains(error, ex.Message);
                if (error == "line 2 failed") Assert.Contains("-A INPUT -j ACCEPT", ex.Message);
            }
            var call = Assert.Single(os.Calls);
            Assert.Equal("iptables-restore", call.Binary);
            Assert.Equal("--noflush --noclear", call.Arguments);
            Assert.Equal("*filter\n-A INPUT -j ACCEPT\nCOMMIT\n\n", call.Text.Replace("\r", ""));
            Assert.False(call.Input.CanWrite);
            Assert.True(call.Process.IsDisposed);
        }
        finally { client.EndTransactionRollback(); }
    }
    [Theory]
    [InlineData("--noclear", "", 0, true)] [InlineData("", "--noclear", 0, true)]
    [InlineData("", "", 0, false)] [InlineData("--noclear", "denied", 1, false)]
    public void PatchedBinaryCheck(string output, string error, int exit, bool success)
    {
        var os = new ScriptedSystem { Respond = (_, _) => new(output, error, exit) };
        var adapter = new IPTablesRestoreAdapter();
        var system = new IpTablesSystem(os, adapter);
        if (success) adapter.CheckBinary(system, 4);
        else Assert.Throws<IpTablesNetException>(() => adapter.CheckBinary(system, 4));
        Assert.True(Assert.Single(os.Calls).Process.IsDisposed);
    }
    [Fact]
    public void StartFailureCanBeRolledBack()
    {
        var os = new ScriptedSystem { Respond = (_, _) => throw new InvalidOperationException("start") };
        using var client = new IpTablesSystem(os, new IPTablesRestoreAdapter()).GetTableAdapter(4);
        client.StartTransaction(); client.AddRule("-A INPUT -j ACCEPT");
        Assert.Throws<InvalidOperationException>(() => client.EndTransactionCommit());
        client.EndTransactionRollback();
    }
}
