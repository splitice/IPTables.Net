using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using IPTables.Net.Iptables.IpSet.Parser;
using IPTables.Net.Netfilter;
using IPTables.Net.Supporting;

namespace IPTables.Net.Iptables.IpSet
{
    /// <summary>
    /// A IPSet "set" possibly containing "entries"
    /// </summary>
    public class IpSetSet
    {
        #region Fields
        private String _name;
        private IpSetType _type;
        private int _timeout;
        private int _hashSize = 1024;
        private int _maxElem = 65536;
        private List<IpSetEntry> _entries = new List<IpSetEntry>();
        private IpTablesSystem _system;
        #endregion

        #region Properties
        public string Name
        {
            get { return _name; }
            set { _name = value; }
        }

        public IpSetType Type
        {
            get { return _type; }
            set { _type = value; }
        }

        public int Timeout
        {
            get { return _timeout; }
            set { _timeout = value; }
        }

        public int MaxElem
        {
            get { return _maxElem; }
            set { _maxElem = value; }
        }

        public int HashSize
        {
            get { return _hashSize; }
            set { _hashSize = value; }
        }

        public List<IpSetEntry> Entries
        {
            get { return _entries; }
        }
        #endregion

        #region Constructor

        public IpSetSet(IpSetType type, string name, int timeout, IpTablesSystem system)
        {
            _type = type;
            _name = name;
            _timeout = timeout;
            _system = system;
        }

        internal IpSetSet(IpTablesSystem system)
        {
            _system = system;
        }

        #endregion

        #region Methods

        public String GetCommand()
        {
            String type = IpSetTypeHelper.TypeToString(_type);
            String command = String.Format("{0} {1} family inet hashsize {2} maxelem {3}", _name, type, _hashSize, _maxElem);
            return command;
        }

        public String GetFullCommand()
        {
            return "create " + GetCommand();
        }

        public IEnumerable<String> GetEntryCommands()
        {
            List<String> ret = new List<string>();
            foreach (var entry in Entries)
            {
                ret.Add("add "+_name+" "+entry.GetKeyCommand());
            }
            return ret;
        }

        #endregion

        public void DeleteSet()
        {
            throw new NotImplementedException();
        }

        public static IpSetSet Parse(String rule, IpTablesSystem system)
        {
            IpSetSet set = new IpSetSet(system);
            string[] arguments = ArgumentHelper.SplitArguments(rule);
            var parser = new IpSetSetParser(arguments, set);

            for (int i = 0; i < arguments.Length; i++)
            {
                i += parser.FeedToSkip(i);
            }

            return set;
        }
    }
}
