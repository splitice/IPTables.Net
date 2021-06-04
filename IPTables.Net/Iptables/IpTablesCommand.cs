using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using IPTables.Net.Exceptions;
using IPTables.Net.Iptables.Modules;
using IPTables.Net.Netfilter;
using IPTables.Net.Supporting;

namespace IPTables.Net.Iptables
{
    public class IpTablesCommand
    {
        private IpTablesCommandType _type;
        private int _offset;
        private IpTablesRule _rule;
        public String ChainName;
        public string Table { get; set; }

        public IpTablesCommandType Type
        {
            get => _type;
            set => _type = value;
        }

        public int Offset
        {
            get => _offset;
            set => _offset = value;
        }

        public IpTablesRule Rule
        {
            get => _rule;
            set => _rule = value;
        }

        public IpTablesCommand(String chainName, String table, IpTablesCommandType type = IpTablesCommandType.Unknown, int offset = -1, IpTablesRule rule = null)
        {
            ChainName = chainName;
            Table = table;
            _type = type;
            _offset = offset;
            _rule = rule;
        }


        public String ToString()
        {
            if (_type == IpTablesCommandType.Add) return _rule.GetCommand();
            if (_type == IpTablesCommandType.Delete) return String.Format("-D {0} {1}", ChainName, _offset + 1);
            if (_type == IpTablesCommandType.Replace) return String.Format("-R {0} {1} {2}", ChainName, _offset + 1, _rule.GetCommand(true).Substring(3));
            if (_type == IpTablesCommandType.Insert) return String.Format("-I {0} {1} {2}", ChainName, _offset + 1, _rule.GetCommand(true).Substring(3));

            throw new Exception("Unknown command type");
        }

        public static IpTablesCommand Parse(String rule, NetfilterSystem system, IpTablesChainSet chains,
            int version = 4, String defaultTable = "filter")
        {
            CommandParser parser;
            return Parse(rule, system, chains, out parser, version, defaultTable);
        }

        internal static IpTablesCommand Parse(String rule, NetfilterSystem system, IpTablesChainSet chains,
            out CommandParser parserOut, int version = 4, String defaultTable = "filter")
        {
            Debug.Assert(chains.IpVersion == version);
            string[] arguments = ArgumentHelper.SplitArguments(rule);
            int count = arguments.Length;
            var ipRule = new IpTablesRule(system, new IpTablesChain(defaultTable, null, version, system));
            var ipCmd = new IpTablesCommand(null, defaultTable, IpTablesCommandType.Unknown, -1, ipRule);

            var parser = new CommandParser(arguments, ipCmd, chains, version);
            parserOut = parser;
            try
            {
                bool not = false;
                for (int i = 0; i < count; i++)
                {
                    if (arguments[i] == "!")
                    {
                        not = true;
                        continue;
                    }
                    i += parser.FeedToSkip(i, not);
                    not = false;
                }
            }
            catch (Exception ex)
            {
                if (ex is IpTablesParserException) throw;
                throw new IpTablesParserException(rule, ex);
            }

            return ipCmd;
        }

        public static IpTablesCommandType GetCommandType(string option)
        {
            switch (option)
            {
                case "-A":
                    return IpTablesCommandType.Add;
                case "-D":
                    return IpTablesCommandType.Delete;
                case "-I":
                    return IpTablesCommandType.Insert;
                case "-R":
                    return IpTablesCommandType.Replace;
            }

            throw new Exception(String.Format("Invalid option {0}", option));
        }
    }
}
