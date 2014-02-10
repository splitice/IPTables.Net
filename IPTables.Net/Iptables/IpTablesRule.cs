using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using SystemInteract;
using IPTables.Net.Common;
using IPTables.Net.Iptables.Modules;
using IPTables.Net.Iptables.Modules.Core;

namespace IPTables.Net.Iptables
{
    public class IpTablesRule : IEquatable<IpTablesRule>
    {
        //Stats
        private readonly Dictionary<String, IIpTablesModuleGod> _modules = new Dictionary<String, IIpTablesModuleGod>();
        public long Bytes = 0;
        public long Packets = 0;
        public IpTablesChain Chain;

        public String Table
        {
            get
            {
                return Chain.Table;
            }
        }

        public String ChainName
        {
            get
            {
                return Chain.Name;
            }
        }

        public int Position
        {
            get
            {
                return Chain.Rules.IndexOf(this) + 1;
            }
        }
        private ISystemFactory _system;

        internal ISystemFactory System
        {
            get
            {
                return _system;
            }
        }

        public IpTablesRule(ISystemFactory system, IpTablesChain chain)
        {
            _system = system;
            Chain = chain;
        }

        public bool Equals(IpTablesRule rule)
        {
            return _modules.DictionaryEqual(rule.ModulesInternal);
        }

        public override bool Equals(object obj)
        {
            if (obj is IpTablesRule)
            {
                return Equals(obj as IpTablesRule);
            }
 	        return base.Equals(obj);
        }

        internal Dictionary<String, IIpTablesModuleGod> ModulesInternal
        {
            get { return _modules; }
        }

        public IEnumerable<IIpTablesModule> Modules
        {
            get
            {
                return _modules.Values.Select((a) => a as IIpTablesModule);
            }
        }


        public String GetCommand()
        {
            String command = "-t " + Table;

            foreach (var e in _modules)
            {
                if (command.Length != 0)
                {
                    command += " ";
                }
                if (e.Value.NeedsLoading)
                {
                    command += "-m " + e.Key + " ";
                }
                command += e.Value.GetRuleString();
            }
            return command;
        }

        public String GetFullCommand(String chain, String opt = "-A")
        {
            String command = opt + " " + chain + " ";
            if (opt == "-R")
            {
                if (Position == -1)
                {
                    throw new Exception("This rule does not have a specific position and hence can not be located for replace");
                }
                command += Position + " ";
            }
            command += GetCommand();
            return command;
        }

        public void Add(String chain)
        {
            String command = GetFullCommand(chain);
            ExecutionHelper.ExecuteIptables(_system, command);
        }

        public void Delete(String chain, bool usingPosition = true)
        {
            String command;
            if (usingPosition)
            {
                command = "-D "+chain+" "+Position;
                var table = GetModule<CoreModule>("core").Table;
                if (!String.IsNullOrEmpty(table) && table != "filter")
                {
                    command += " -t "+table;
                }
            }
            else
            {
                command = GetFullCommand(chain, "-D");
            }
            ExecutionHelper.ExecuteIptables(_system, command);
        }

        internal IIpTablesModuleGod GetModuleForParseInternal(string name, Type moduleType)
        {
            if (_modules.ContainsKey(name))
            {
                return _modules[name];
            }

            var module = (IIpTablesModuleGod)Activator.CreateInstance(moduleType);
            _modules.Add(name, module);
            return module;
        }

        public IIpTablesModule GetModuleForParse(string name, Type moduleType)
        {
            return GetModuleForParseInternal(name, moduleType);
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

        public static IpTablesRule Parse(String rule, ISystemFactory system, IpTablesChainSet chains)
        {
            string[] arguments = SplitArguments(rule);
            int count = arguments.Length;
            var ipRule = new IpTablesRule(system, null);
            var parser = new RuleParser(arguments, ipRule, chains);

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

            ipRule.Chain = parser.Chain;

            return ipRule;
        }

        public T GetModule<T>(string moduleName) where T: class, IIpTablesModule
        {
            if (!_modules.ContainsKey(moduleName)) return null;
            return _modules[moduleName] as T;
        }

        public T GetModuleOrLoad<T>(string moduleName) where T : class, IIpTablesModule
        {
            return GetModuleForParse(moduleName, typeof(T)) as T;
        }

        public void Replace(String chain, IpTablesRule withRule)
        {
            withRule.Position = Position;
            String command = withRule.GetFullCommand(chain, "-R");
            ExecutionHelper.ExecuteIptables(_system, command);
        }
    }
}