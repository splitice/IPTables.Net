using System;
using System.Linq;
using IPTables.Net.Exceptions;
using IPTables.Net.IpSet;
namespace IPTables.Net.Tests;
public class IpSetModeTests
{
    [Theory]
    [InlineData(IpSetSyncMode.SetOnly, false, false)] [InlineData(IpSetSyncMode.SetOnly, true, false)]
    [InlineData(IpSetSyncMode.SetAndEntries, false, true)] [InlineData(IpSetSyncMode.SetAndEntries, true, true)]
    [InlineData(IpSetSyncMode.SetAndEntriesOnCreate, false, true)] [InlineData(IpSetSyncMode.SetAndEntriesOnCreate, true, false)]
    public void ModesControlEntryPopulation(IpSetSyncMode mode, bool exists, bool populate)
    {
        var os = new ScriptedSystem { Respond = (_, a) => new(a == "save" && exists ? "create demo hash:ip\n" : "") };
        var system = new IpTablesSystem(os, null);
        var desired = new IpSetSets(new[] { "create demo hash:ip", "add demo 192.0.2.1" }, system);
        desired.Sets.Single().SyncMode = mode; desired.Sync();
        var text = string.Join("", os.Calls.Select(c => c.Text));
        Assert.Equal(populate, text.Contains("add demo 192.0.2.1"));
        Assert.Equal(!exists, text.Contains("create demo"));
        Assert.False(system.SetAdapter.InTransaction);
    }
    [Theory]
    [InlineData(0)] [InlineData(1)] [InlineData(2)]
    public void DeletionRequiresExplicitPredicate(int policy)
    {
        var os = new ScriptedSystem { Respond = (_, a) => new(a == "save" ? "create old hash:ip\ncreate foreign hash:ip\n" : "") };
        var system = new IpTablesSystem(os, null);
        new IpSetSets(system).Sync(policy == 0 ? null : s => policy == 2 && s.Name == "old");
        var text = string.Join("", os.Calls.Select(c => c.Text));
        Assert.Equal(policy == 2, text.Contains("destroy old")); Assert.DoesNotContain("destroy foreign", text);
    }
    [Fact]
    public void ReplacementPreservesSetOnlyEntriesAndRejectsCollisionsAndFamilyChanges()
    {
        var saved = "create demo hash:ip\nadd demo 192.0.2.1 timeout 10\n";
        var os = new ScriptedSystem { Respond = (_, a) => new(a == "save" ? saved : "") };
        var system = new IpTablesSystem(os, null);
        var desired = new IpSetSets(new[] { "create demo hash:ip hashsize 2048" }, system);
        desired.Sets.Single().SyncMode = IpSetSyncMode.SetOnly;
        desired.Sync();
        var text = os.Calls.Last().Text;
        Assert.True(text.IndexOf("add demo_S 192.0.2.1 timeout 10", StringComparison.Ordinal) < text.IndexOf("swap demo_S demo", StringComparison.Ordinal));
        saved += "create demo_S hash:ip\n";
        Assert.Throws<IpTablesNetException>(() => desired.Sync()); Assert.False(system.SetAdapter.InTransaction);
        saved = "create demo hash:ip\n"; desired.Sets.Single().Family = "inet6";
        Assert.Throws<IpTablesNetException>(() => desired.Sync()); Assert.False(system.SetAdapter.InTransaction);
    }
}
