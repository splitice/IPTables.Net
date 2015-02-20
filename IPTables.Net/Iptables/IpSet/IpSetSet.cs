using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

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

        public IpSetSet(IpSetType type, string name, int timeout)
        {
            _type = type;
            _name = name;
            _timeout = timeout;
        }

        #endregion

        #region Methods

        public String GetCommand()
        {
            String type = IpSetTypeHelper.TypeToString(_type);
            String command = String.Format("add {0} {1} family inet hashsize {2} maxelem {3}", _name, type, _hashSize, _maxElem);
            return command;
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
    }
}
