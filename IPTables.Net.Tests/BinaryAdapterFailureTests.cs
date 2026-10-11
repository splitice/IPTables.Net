using System;
using System.Linq;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Adapter;

namespace IPTables.Net.Tests;
public class BinaryAdapterFailureTests
{
    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)] [InlineData(17)]
    public void MutationsReportFailuresAndDispose(int exit)
    {
        foreach (var operation in new[] { "add", "replace", "delete", "flush" })
        {
            var os = new ScriptedSystem { Respond = (_, _) => new("", "detail", exit) };
            var system = new IpTablesSystem(os, new IPTablesBinaryAdapter());
            using var client = system.GetTableAdapter(4);
            var rule = IpTablesRule.Parse("-A INPUT -j ACCEPT", system, new IpTablesChainSet(4), 4);
            rule.Chain.AddRule(rule);
            Action action = operation switch {
                "add" => () => client.AddRule(rule), "replace" => () => client.ReplaceRule(rule),
                "delete" => () => client.DeleteRule(rule), _ => () => client.DeleteChain("filter", "custom", true)
            };
            if (exit == 0) action();
            else Assert.Contains("detail", Assert.Throws<IpTablesNetException>(action).Message);
            Assert.All(os.Calls, call => Assert.True(call.Process.IsDisposed));
            if (operation == "flush")
                Assert.Equal(exit == 0 ? new[] { "-t filter -F custom", "-t filter -X custom" } : new[] { "-t filter -F custom" }, os.Calls.Select(c => c.Arguments));
        }
    }
    [Theory]
    [InlineData("", "denied", 1)] [InlineData("*filter\nCOMMIT", "denied", 1)]
    [InlineData("", "denied", 0)] [InlineData("", "", 2)]
    public void FailedListingsAreNeverAccepted(string output, string error, int exit)
    {
        var os = new ScriptedSystem { Respond = (_, _) => new(output, error, exit) };
        using var client = new IpTablesSystem(os, new IPTablesBinaryAdapter()).GetTableAdapter(4);
        Assert.Throws<IpTablesNetException>(() => client.ListRules("filter"));
        Assert.True(Assert.Single(os.Calls).Process.IsDisposed);
    }
    [Fact]
    public void HasChainOnlySuppressesMissingChain()
    {
        var os = new ScriptedSystem();
        using var client = new IpTablesSystem(os, new IPTablesBinaryAdapter()).GetTableAdapter(4);
        Assert.True(client.HasChain("filter", "custom"));
        os.Respond = (_, _) => new("", "No chain/target/match by that name.", 1);
        Assert.False(client.HasChain("filter", "custom"));
        os.Respond = (_, _) => new("", "Permission denied", 1);
        Assert.Throws<IpTablesNetException>(() => client.HasChain("filter", "custom"));
        os.Respond = (_, _) => throw new InvalidOperationException("start failed");
        Assert.Throws<InvalidOperationException>(() => client.AddChain("filter", "custom"));
    }
}
