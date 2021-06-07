using System.Collections.Generic;
using System.Linq;
using System.Xml;
using System.Xml.Linq;
using SystemInteract;

namespace IPTables.Net.NfAcct
{
    public class NfAcct
    {
        private ISystemFactory _system;

        public NfAcct(ISystemFactory system)
        {
            _system = system;
        }

        private NfAcctUsage FromXml(string output, string name)
        {
            XDocument doc;
            try
            {
                doc = XDocument.Parse(output);
            }
            catch (XmlException)
            {
                return null;
            }

            var usages = from node in doc.Descendants("obj")
                where node.Descendants("name").First().Value == name
                select new NfAcctUsage(node.Descendants("name").First().Value,
                    ulong.Parse(node.Descendants("pkts").First().Value),
                    ulong.Parse(node.Descendants("bytes").First().Value));

            return usages.FirstOrDefault();
        }

        public NfAcctUsage Get(string name, bool reset = false)
        {
            var cmd = "get {0} xml";
            if (reset) cmd += " reset";

            string output, error;
            using (var process = _system.StartProcess("/usr/sbin/nfacct", string.Format(cmd, name)))
            {
                ProcessHelper.ReadToEnd(process, out output, out error);
            }

            if (output.Trim().Length == 0) return null;

            return FromXml(output, name);
        }

        public bool Exist(string name)
        {
            return Get(name) != null;
        }

        public void Add(string name)
        {
            var cmd = "add {0}";
            using (var process = _system.StartProcess("/usr/sbin/nfacct", string.Format(cmd, name)))
            {
                string output, error;
                ProcessHelper.ReadToEnd(process, out output, out error);
            }
        }

        public void Delete(string name)
        {
            var cmd = "del {0}";
            using (var process = _system.StartProcess("/usr/sbin/nfacct", string.Format(cmd, name)))
            {
                string output, error;
                ProcessHelper.ReadToEnd(process, out output, out error);
            }
        }

        public List<NfAcctUsage> List(bool reset = false)
        {
            var cmd = "list xml";
            if (reset) cmd += " reset";

            string output, error;
            using (var process = _system.StartProcess("/usr/sbin/nfacct", cmd))
            {
                ProcessHelper.ReadToEnd(process, out output, out error);
            }

            //No XML returned for empty
            if (output.Trim().Length == 0) return new List<NfAcctUsage>();

            var doc = XDocument.Parse(output);
            var usages = from node in doc.Descendants("obj")
                select new NfAcctUsage(node.Descendants("name").First().Value,
                    ulong.Parse(node.Descendants("bytes").First().Value),
                    ulong.Parse(node.Descendants("pkts").First().Value));

            return usages.ToList();
        }
    }
}