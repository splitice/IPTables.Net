using System;
using System.Collections.Generic;
using System.Diagnostics;
using SystemInteract;
using IPTables.Net.Common;
using IPTables.Net.Iptables.Modules;
using IPTables.Net.Iptables.Modules.Base;

namespace IPTables.Net.Iptables
{
    public class IpTablesRule : IEquatable<IpTablesRule>
    {
        //Stats
        private readonly Dictionary<String, IIptablesModule> _modules = new Dictionary<String, IIptablesModule>();
        public long Bytes = 0;
        public long Packets = 0;
        private ISystemFactory _system;

        public IpTablesRule(ISystemFactory system)
        {
            _system = system;
        }

        public bool Equals(IpTablesRule rule)
        {
            return _modules.DictionaryEqual(rule.Modules);
        }

        public override bool Equals(object obj)
        {
            if (obj is IpTablesRule)
            {
                return Equals(obj as IpTablesRule);
            }
 	        return base.Equals(obj);
        }

        public Dictionary<String, IIptablesModule> Modules
        {
            get { return _modules; }
        }


        public String GetCommand(String table)
        {
            String command = "";

            if (table != "filter")
            {
                command = "-t " + table;
            }

            foreach (var e in _modules)
            {
                if (command.Length != 0)
                {
                    command += " ";
                }
                if (e.Key != "core")
                {
                    command += "-m " + e.Key + " ";
                }
                command += e.Value.GetRuleString();
            }

            return command;
        }

        public void Add(String table, String chain)
        {
            String command = " -A " + chain + " " + GetCommand(table);
            var process = _system.StartProcess("iptables", command);
            process.WaitForExit();
        }

        public void Delete(String table, String chain)
        {
            String command = " -D " + chain + " " + GetCommand(table);
            var process = _system.StartProcess("iptables", command);
            process.WaitForExit();
        }

        public IIptablesModule GetModuleForParse(string name, Type moduleType)
        {
            if (_modules.ContainsKey(name))
            {
                return _modules[name];
            }

            var module = (IIptablesModule) Activator.CreateInstance(moduleType);
            _modules.Add(name, module);
            return module;
        }

        public static string[] SplitArguments(string commandLine)
        {
            char[] parmChars = commandLine.ToCharArray();
            bool inSingleQuote = false;
            bool inDoubleQuote = false;
            for (int index = 0; index < parmChars.Length; index++)
            {
                if (parmChars[index] == '"' && !inSingleQuote)
                {
                    inDoubleQuote = !inDoubleQuote;
                    parmChars[index] = '\n';
                }
                if (parmChars[index] == '\'' && !inDoubleQuote)
                {
                    inSingleQuote = !inSingleQuote;
                    parmChars[index] = '\n';
                }
                if (!inSingleQuote && !inDoubleQuote && parmChars[index] == ' ')
                    parmChars[index] = '\n';
            }
            return (new string(parmChars)).Split(new[] {'\n'}, StringSplitOptions.RemoveEmptyEntries);
        }

        public static IpTablesRule Parse(String rule, ISystemFactory system, out String chain)
        {
            string[] arguments = SplitArguments(rule);
            int count = arguments.Length;
            var ipRule = new IpTablesRule(system);
            var parser = new RuleParser(arguments, ipRule);

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

            chain = parser.Chain;

            return ipRule;
        }
    }
}