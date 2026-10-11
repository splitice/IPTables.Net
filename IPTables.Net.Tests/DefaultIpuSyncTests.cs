using System;
using System.Collections.Generic;
using System.Linq;
using IPTables.Net.IpUtils.Sync;
using IPTables.Net.IpUtils.Utils;
namespace IPTables.Net.Tests;
public class DefaultIpuSyncTests
{
    private static IpObject Item(string key) => new() { Pairs = new() { ["to"] = key } };
    private sealed class Controller : IpController
    {
        public List<IpObject> State = new(); public List<string> Log = new(); public string Fail;
        public Controller() : base("route", null) { }
        public override void Add(IpObject item) { Log.Add("add " + item.Pairs["to"]); if (Fail == "add") throw new InvalidOperationException("add"); State.Add(item); }
        public override void Delete(IpObject item) { Log.Add("del " + item.Pairs["to"]); if (Fail == "del") throw new InvalidOperationException("del"); State.RemoveAll(x => x.Equals(item)); }
    }
    [Theory]
    [InlineData("", "", "")] [InlineData("a", "a", "")]
    [InlineData("a", "b", "del a,add b")] [InlineData("a,b", "b,c", "del a,add c")]
    [InlineData("a,a,b", "a,a", "del b")] [InlineData("", "a,a", "add a")]
    public void SetDifferencesAndRepeatAreIdempotent(string current, string desired, string expected)
    {
        static List<IpObject> Parse(string input) => input.Split(',', StringSplitOptions.RemoveEmptyEntries).Select(Item).ToList();
        var controller = new Controller { State = Parse(current) }; var sync = new DefaultIpuSync(controller, () => controller.State);
        sync.Sync(Parse(desired)); Assert.Equal(expected, string.Join(",", controller.Log));
        controller.Log.Clear(); sync.Sync(Parse(desired)); Assert.Empty(controller.Log);
        Assert.True(new HashSet<IpObject>(Parse(desired)).SetEquals(controller.State));
    }
    [Theory]
    [InlineData("get", "", "a")] [InlineData("del", "del a", "a")] [InlineData("add", "del a,add b", "")]
    public void FailuresPropagateWithoutPretendingToRollback(string fail, string expected, string state)
    {
        var controller = new Controller { State = new() { Item("a") }, Fail = fail };
        var sync = new DefaultIpuSync(controller, () => fail == "get" ? throw new InvalidOperationException("get") : controller.State);
        Assert.Equal(fail, Assert.Throws<InvalidOperationException>(() => sync.Sync(new[] { Item("b") })).Message);
        Assert.Equal(expected, string.Join(",", controller.Log)); Assert.Equal(state, string.Join(",", controller.State.Select(x => x.Pairs["to"])));
    }
}
