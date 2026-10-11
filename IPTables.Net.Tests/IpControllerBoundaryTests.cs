using System;
using IPTables.Net.Exceptions;
using IPTables.Net.IpUtils.Utils;
namespace IPTables.Net.Tests;
public class IpControllerBoundaryTests
{
    [Theory]
    [InlineData(null, false)] [InlineData("blue", true)] [InlineData("default", false)] [InlineData("all", false)]
    public void ListingAddsOnlyAnExplicitTableWithoutOverwritingOutput(string table, bool added)
    {
        var fake = new ScriptedSystem { Respond = (_, _) => new("default via 192.0.2.1 dev eth0\n192.0.2.0/24 dev eth1 table green\n") };
        var routes = new IpRouteController(fake).GetAll(table);
        Assert.Equal(2, routes.Count); Assert.Equal(added, routes[0].Pairs.ContainsKey("table"));
        if (added) Assert.Equal(table, routes[0].Pairs["table"]);
        Assert.Equal("green", routes[1].Pairs["table"]);
        Assert.Equal(table == null ? "route show" : "route show table " + table, Assert.Single(fake.Calls).Arguments);
    }
    [Fact]
    public void EmptyListingsAndMulticastParsing()
    {
        var routes = new IpRouteController(new ScriptedSystem()); Assert.Empty(routes.GetAll());
        Assert.Empty(new IpRuleController(new ScriptedSystem()).GetAll());
        var route = routes.ParseObject("multicast 224.0.0.0/4 dev eth0 onlink");
        Assert.Equal("224.0.0.0/4", route.Pairs["multicast"]); Assert.Contains("onlink", route.Singles);
        Assert.Equal("multicast 224.0.0.0/4 dev eth0 onlink", string.Join(" ", routes.ExportObject(route)));
    }
    [Theory]
    [InlineData(false, "default dev")] [InlineData(false, "onlink")]
    [InlineData(false, "default dev eth0 dev eth1")] [InlineData(true, "bad: from all")]
    [InlineData(true, "100: from")] [InlineData(true, "not")]
    public void MalformedListingIncludesOffendingLine(bool rule, string line)
    {
        var fake = new ScriptedSystem { Respond = (_, _) => new(line) };
        var error = Assert.Throws<IpTablesNetException>(() => { if (rule) new IpRuleController(fake).GetAll(); else new IpRouteController(fake).GetAll(); });
        Assert.Contains(line, error.Message); Assert.NotNull(error.InnerException);
    }
    [Theory]
    [InlineData(false, "", "")] [InlineData(true, "", "denied")] [InlineData(false, "failed", "")]
    public void AllOperationsRejectNonzeroExit(bool rule, string output, string error)
    {
        var fake = new ScriptedSystem { Respond = (_, _) => new(output, error, 2) };
        IpController controller = rule ? new IpRuleController(fake) : new IpRouteController(fake);
        Assert.Contains("exited with 2", Assert.Throws<IpControllerException>(() => controller.Add("default")).Message);
        Assert.Throws<IpControllerException>(() => controller.Delete("default"));
        Assert.Throws<IpControllerException>(() => { if (rule) ((IpRuleController)controller).GetAll(); else ((IpRouteController)controller).GetAll(); });
        Assert.All(fake.Calls, call => Assert.True(call.Process.IsDisposed));
    }
}
