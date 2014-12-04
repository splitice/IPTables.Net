# IPTables.Net

[![Build Status](https://travis-ci.org/splitice/IPTables.Net.png?branch=master)](https://travis-ci.org/splitice/IPTables.Net)

A library for for interfacing with Linux the IPTables utility

## Features

-   String rule parsing

-   IPTables save rule parsing from either a local or remote system (SSH
    via SystemInteract.Remote)

-   Class based representation of IPTables module options

-   Automatic Synchronization of rules with system (Insert, Delete,
    Replace)

## Examples

### Parsing an IPTables Rule:

    String rule = "-A INPUT -p tcp ! -f -j DROP -m tcp --sport 53 -m comment --comment 'this is a test rule'";
    IpTablesChainSet chains = new IpTablesChainSet();
    IpTablesRule irule = IpTablesRule.Parse(rule, null, chains);

### Deleting all defined rules:

    var system = new IPTablesSystem();
    foreach(var rule in system.GetRules("nat")){
        rule.Delete();
    }

### Syncing a chain set:

    IpTablesChain chain = new IpTablesChain("filter","INPUT",system); 
    chain.AddRule("-A INPUT !-f"); 
    system.GetChain("filter","INPUT").Sync(chain);
	
### More Examples
For more examples see the Tests project.

## Contributing
Pull-Requests and Patches are very welcome.