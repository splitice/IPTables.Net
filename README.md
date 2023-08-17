# IPTables.Net

[![CircleCI](https://circleci.com/gh/splitice/IPTables.Net.svg?style=svg)](https://circleci.com/gh/splitice/IPTables.Net)


A library for for interfacing C# with Linux IPTables

## Features

-  String rule parsing to class based representation
-  IPTables save rule parsing from either a local or remote system (SSH via SystemInteract.Remote)
-  Automatic Synchronization of rules with system (Insert, Delete, Replace)
-  IPSet support
-  Support for both IPv4 and IPv6

## Adapters

An adapter is used to communicate with IPTables. Depending on your implementation / requirements you may wish to choose a specific adapter.

### IPTables Binary
This is the most simple adapter and the default. It does not have any transactional support (make many changes at once) and is not high performing when making many changes and dealing with complex rule sets. This adapter requires only the ```iptables-save``` and ```iptables``` binaries to work.

### IPTables Restore
This is a bit more advanced instead of using ```iptables```, ```iptables-restore``` is used. This provides transactions on a per-table basis and higher performance. Unfortunately due to how ```iptables-restore``` is implemented this adapter does not play nice with other rules loaded outside of this script unless the patch supplied is applied (which is specific to an IPTables version).

### IPTables Library
This is the most advanced method. Supports transactions and is very high performing. This method uses a custom shared library to communicate and control ```libiptc``` directly. No need for any iptables binaries (when in a transaction). The library ```iptchelper``` needs to be compiled, if compiling on an IPTables version less than 1.4.18 (ish) you will need to supply the pre-processor macro ```OLD_IPTABLES``` for the compilation to succeed. See the travis file for an example on how to provide this option, and how to compile the library. ```install.sh``` has been provided as a one click installer for new IPTables versions.

This method is only compatible locally, will not work over SSH (SystemInteract.Remote).

## Examples

For more examples see the Tests project. These are generally more full featured and up-to-date.

### Parsing an IPTables Rule:
```csharp
    String rule = "-A INPUT -p tcp ! -f -j DROP -m tcp --sport 53 -m comment --comment 'this is a test rule'";
    IpTablesChainSet chains = new IpTablesChainSet();
    IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);
```

### Deleting all IPv4 defined rules:
```csharp
    var system = new IPTablesSystem(system: new LocalFactory(), tableAdapter: new IPTablesBinaryAdapter());
    foreach(var rule in system.GetRules(table: "nat", ipVersion: 4)){
        rule.Delete();
    }
```

### Syncing a chain set:
```csharp
    IpTablesChain chain = new IpTablesChain("filter","INPUT",system); 
    chain.AddRule("-A INPUT !-f"); 
    system.GetChain("filter","INPUT").Sync(chain);
```

### Adding rule to system
```csharp
// Create rule
String rule = "-A INPUT -p tcp ! -f -j DROP -m tcp --sport 53 -m comment --comment 'this is a test rule'";
IpTablesChainSet chains = new IpTablesChainSet();
IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

// Add rule
var system = new IPTablesSystem(system: new LocalFactory(), tableAdapter: new IPTablesBinaryAdapter());
IIPTablesAdapter table = ipTablesSystem.GetTableAdapter(version: 4);
table.AddRule(irule);
```

## Contributing
Pull-Requests and Patches are very welcome.
