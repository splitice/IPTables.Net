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

        private bool WriteOutputLine(StreamWriter output, String line)
        {
            if (!output.BaseStream.CanWrite)
            {
                return false;
            }
            output.WriteLine(line);
            return true;
        }

        public bool WriteOutput(StreamWriter output)
        {
            bool res;
            foreach (var table in _tables)
            {
                res = WriteOutputLine(output, "*" + table.Key);
                if (!res)
                {
                    return true;
                }


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
                    else if (table.Key == "raw")
                    {
                        isInternal = (chain == "PREROUTING" || chain == "OUTPUT");
                    }

                    if (isInternal)
                    {
                        res = WriteOutputLine(output, ":" + chain + " ACCEPT [0:0]");
                    }
                    else
                    {
                        res = WriteOutputLine(output, ":" + chain + " - [0:0]");
                    } 
                    if (!res)
                    {
                        return true;
                    }
                }

                foreach (var command in table.Value.Commands)
                {
                    Console.WriteLine(command);
                    res = WriteOutputLine(output, command);
                    if (!res)
                    {
                        return true;
                    }
                }

                res = WriteOutputLine(output, "COMMIT");
                if (!res)
                {
                    return true;
                }
                res = WriteOutputLine(output, "");
                if (!res)
                {
                    return true;
                }
            }

            if (_tables.Count != 0)
            {
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
