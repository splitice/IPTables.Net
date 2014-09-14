using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace IPTables.Net.Iptables.Adapter.Client.Helper
{
    class IPTablesRestoreTableBuilder
    {
        private class Table
        {
            internal readonly HashSet<String> Chains = new HashSet<string>();
            internal readonly List<String> Commands = new List<string>();
        }
        private readonly Dictionary<String, Table> _tables = new Dictionary<String, Table>();

        public void AddChain(String table, String chain)
        {
            if (!_tables.ContainsKey(table))
            {
                _tables.Add(table, new Table());
            }
            var chainTable = _tables[table];

            if (chainTable.Chains.Contains(chain))
            {
                throw new Exception("Chain has already been added");
            }
            chainTable.Chains.Add(chain);
        }

        public void AddCommand(String table, String ruleCommand)
        {
            if (!_tables.ContainsKey(table))
            {
                _tables.Add(table, new Table());
            }
            var commandTable = _tables[table];

            //iptables-restore doesnt support ' quotes
            ruleCommand = ruleCommand.Replace('\'', '"');


            commandTable.Commands.Add(ruleCommand);
        }

        public bool WriteOutput(StreamWriter output)
        {
            foreach (var table in _tables)
            {
                output.WriteLine("*" + table.Key);

                foreach (var chain in table.Value.Chains)
                {
                    bool isInternal = false;
                    if (table.Key == "nat")
                    {
                        isInternal = (chain == "PREROUTING" || chain == "POSTROUTING");
                    }
                    else if (table.Key == "filter")
                    {
                        isInternal = (chain == "INPUT" || chain == "FORWARD" || chain == "OUTPUT");
                    }

                    if (isInternal)
                    {
                        output.WriteLine(":" + chain+" ACCEPT [0:0]");
                    }
                    else
                    {
                        output.WriteLine(":" + chain + " - [0:0]");
                    }
                }

                foreach (var command in table.Value.Commands)
                {
                    Console.WriteLine(command);
                    output.WriteLine(command);
                }
            }

            if (_tables.Count != 0)
            {
                output.WriteLine("COMMIT");
                output.WriteLine();
                return true;
            }

            return false;
        }

        public void Clear()
        {
            _tables.Clear();
        }

        public bool HasChain(string table, string chainName)
        {
            if (!_tables.ContainsKey(table))
            {
                return false;
            }

            return _tables[table].Chains.Contains(chainName);
        }

        public bool DeleteChain(string table, string chainName)
        {
            if (!_tables.ContainsKey(table))
            {
                return false;
            }

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
