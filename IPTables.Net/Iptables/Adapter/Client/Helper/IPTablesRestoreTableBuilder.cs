﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using IPTables.Net.Exceptions;
using Serilog;

namespace IPTables.Net.Iptables.Adapter.Client.Helper
{
    internal class IPTablesRestoreTableBuilder
    {
        protected static readonly ILogger Log = IPTablesLogManager.GetLogger<IPTablesRestoreTableBuilder>();

        private class Table
        {
            internal readonly HashSet<string> Chains = new HashSet<string>();
            internal readonly List<string> Commands = new List<string>();
        }

        private readonly Dictionary<string, Table> _tables = new Dictionary<string, Table>();

        public void AddChain(string table, string chain)
        {
            if (!_tables.ContainsKey(table)) _tables.Add(table, new Table());
            var chainTable = _tables[table];

            if (chainTable.Chains.Contains(chain)) throw new IpTablesNetException("Chain has already been added");
            chainTable.Chains.Add(chain);
        }

        public void AddCommand(string table, string ruleCommand)
        {
            if (!_tables.ContainsKey(table)) _tables.Add(table, new Table());
            var commandTable = _tables[table];

            //iptables-restore doesnt support ' quotes
            ruleCommand = ruleCommand.Replace('\'', '"');


            commandTable.Commands.Add(ruleCommand);
        }

        private bool WriteOutputLine(StreamWriter output, string line)
        {
            if (!output.BaseStream.CanWrite) return false;
            try
            {
                output.WriteLine(line);
                output.Flush();
            }
            catch (IOException)
            {
                return false;
            }

            return true;
        }

        public bool WriteOutput(StreamWriter output)
        {
            bool res;
            foreach (var table in _tables)
            {
                res = WriteOutputLine(output, "*" + table.Key);
                if (!res) return true;


                foreach (var chain in table.Value.Chains)
                {
                    if (IPTablesTables.IsInternalChain(table.Key, chain))
                        res = WriteOutputLine(output, ":" + chain + " ACCEPT [0:0]");
                    else
                        res = WriteOutputLine(output, ":" + chain + " - [0:0]");
                    if (!res) return true;
                }

                foreach (var command in table.Value.Commands)
                {
                    Log.Information("-t " + table.Key + " " + command);
                    res = WriteOutputLine(output, command);
                    if (!res) return true;
                }

                res = WriteOutputLine(output, "COMMIT");
                if (!res) return true;
                res = WriteOutputLine(output, "");
                if (!res) return true;
            }

            if (_tables.Count != 0) return true;

            return false;
        }

        public void Clear()
        {
            _tables.Clear();
        }

        public bool HasChain(string table, string chainName)
        {
            if (!_tables.ContainsKey(table)) return false;

            return _tables[table].Chains.Contains(chainName);
        }

        public bool DeleteChain(string table, string chainName)
        {
            if (!_tables.ContainsKey(table)) return false;

            var chains = _tables[table].Chains;

            if (chains.Contains(chainName))
            {
                chains.Remove(chainName);
                return true;
            }

            return false;
        }
    }
}