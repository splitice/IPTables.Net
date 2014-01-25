IPTables.Net
============

[![Build Status](https://travis-ci.org/splitice/IPTables.Net.png?branch=master)](https://travis-ci.org/splitice/IPTables.Net)

A library for for interfacing with linux IPTables


Example
=======

Parsing an IPTables Rule:
```
String chain;
IpTablesRule irule = IpTablesRule.Parse("-A INPUT -p tcp ! -f -j DROP -m tcp --sport 53 -m comment --comment \"this is a test rule\"", out chain);
```

Deleting all defined rules:
```
var system = new IPTablesSystem();
foreach(var rule in system.GetRules("nat")){
	rule.Delete();
}
```