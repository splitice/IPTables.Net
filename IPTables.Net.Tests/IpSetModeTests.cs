using System;
using System.Linq;
using IPTables.Net.Exceptions;
using IPTables.Net.IpSet;
namespace IPTables.Net.Tests;
public class IpSetModeTests
{
    [Theory]
    [InlineData(0u, 0u, true)]
    [InlineData(16u, 0u, true)]
    [InlineData(16u, 16u, true)]
    [InlineData(0u, 32u, false)]
    [InlineData(16u, 32u, false)]
    public void SetComparisonHonorsOnlyExplicitDesiredSeeds(uint currentSeed, uint desiredSeed, bool equal)
    {
        var current = IpSetSet.Parse($"demo hash:ip initval {currentSeed}", null);
        var desired = IpSetSet.Parse($"demo hash:ip initval {desiredSeed}", null);
        Assert.Equal(equal, current.SetEquals(desired));
        Assert.Equal(equal, current.SetEquals(desired, size: false));
    }

    [Theory]
    [InlineData(0u, 0u, false)]
    [InlineData(16u, 0u, false)]
    [InlineData(16u, 16u, false)]
    [InlineData(0u, 32u, true)]
    [InlineData(16u, 32u, true)]
    public void SeedChangesReplaceExistingSetsAndConverge(uint currentSeed, uint desiredSeed, bool replace)
    {
        var saved = $"create demo hash:ip initval {currentSeed}\nadd demo 192.0.2.1\n";
        var os = new ScriptedSystem { Respond = (_, args) => new(args == "save" ? saved : "") };
        var system = new IpTablesSystem(os, null);
        var desired = new IpSetSets(new[] { $"create demo hash:ip initval {desiredSeed}", "add demo 192.0.2.1" }, system);

        desired.Sync();

        if (replace)
        {
            var restore = Assert.Single(os.Calls, call => call.Arguments == "restore");
            Assert.Equal($"create demo_S hash:ip family inet hashsize 1024 maxelem 65536 initval {desiredSeed}\n" +
                "swap demo_S demo\ndestroy demo_S\nadd demo 192.0.2.1\n", restore.Text.Replace("\r", ""));
            saved = $"create demo hash:ip initval {desiredSeed}\nadd demo 192.0.2.1\n";
        }
        else
            Assert.Equal("save", Assert.Single(os.Calls).Arguments);

        os.Calls.Clear();
        desired.Sync();
        Assert.Equal("save", Assert.Single(os.Calls).Arguments);
        Assert.False(system.SetAdapter.InTransaction);
    }

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
