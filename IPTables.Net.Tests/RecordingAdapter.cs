using System;
using System.Collections.Generic;
using IPTables.Net.Iptables;
using IPTables.Net.Iptables.Adapter;
using IPTables.Net.Iptables.Adapter.Client;
namespace IPTables.Net.Tests;
internal sealed class RecordingAdapter : IpTablesAdapterClientBase, IIPTablesAdapter
{
    public readonly List<string> Log = new();
    public Action<string> OnCall = _ => { };
    public Func<string, IpTablesChainSet> Read;
    public IpTablesSystem System;
    public int Version;
    public IIPTablesAdapterClient GetClient(IpTablesSystem system, int ipVersion = 4) { System = system; Version = ipVersion; return this; }
    private void Call(string text) { Log.Add(text); OnCall(text); }
    public override void StartTransaction() => Call("start");
    public override void EndTransactionCommit() => Call("commit");
    public override void EndTransactionRollback() => Call("rollback");
    public override void Dispose() => Call("dispose");
    public override bool HasChain(string table, string chainName) => ListRules(table).HasChain(chainName, table);
    public override void AddChain(string table, string chainName) => Call($"create {table}/{chainName}");
    public override void DeleteChain(string table, string chainName, bool flush = false) => Call($"delete {table}/{chainName}");
    public override IpTablesChainSet ListRules(string table) { Call("read " + table); return Read?.Invoke(table) ?? new(Version); }
    public override void DeleteRule(string table, string chainName, int position) => Call($"remove {table}/{chainName}/{position}");
    public override void DeleteRule(IpTablesRule rule) => Call("remove " + rule.GetActionCommand());
    public override void InsertRule(IpTablesRule rule) => Call("insert " + rule.GetActionCommand());
    public override void ReplaceRule(IpTablesRule rule) => Call("replace " + rule.GetActionCommand());
    public override void AddRule(IpTablesRule rule) => Call("add " + rule.GetActionCommand());
    public override void AddRule(string rule) => Call("add " + rule);
    public override System.Version GetIptablesVersion() => new(1, 8, 0);
}
