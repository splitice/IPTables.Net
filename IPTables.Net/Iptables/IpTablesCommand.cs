using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using IPTables.Net.Netfilter;

namespace IPTables.Net.Iptables
{
    public class IpTablesCommand
    {
        private Action _action;
        private int _offset;
        private IpTablesRule _rule;

        public Action Command => _action;

        public int Offset => _offset;

        public IpTablesRule Rule => _rule;

        public enum Action
        {
            Add, Delete, Replace
        }

        public IpTablesCommand(Action action, int offset = -1, IpTablesRule rule = null)
        {
            _action = action;
            _offset = offset;
            _rule = rule;
        }

        public String GetCommand()
        {
            if (_action == Action.Add) return _rule.GetCommand();
            if (_action == Action.Delete) return String.Format("-D {0}", _offset);
            if (_action == Action.Replace) return String.Format("-R {0} {1}", _offset, _rule.GetCommand().Substring(3));
        }

        static IpTablesCommand Parse(string command, NetfilterSystem system, IpTablesChainSet chains, int version = 4)
        {
            if (command.StartsWith("-D "))
            {
                return new IpTablesCommand(Action.Delete, int.Parse(command.Substring(3)));
            }

            if (command.StartsWith("-A "))
            {
                return new IpTablesCommand(Action.Add, -1, IpTablesRule.Parse(command, system, chains, version));
            }

            if (command.StartsWith("-R "))
            {
                command = command.Substring(3);
                int idx = int.Parse(command.Substring(command.IndexOf(' ')));
                command = "-A "+command.Substring(command.IndexOf(' '));
                return new IpTablesCommand(Action.Add, idx, IpTablesRule.Parse(command, system, chains, version));
            }

            return null;
        }
    }
}
