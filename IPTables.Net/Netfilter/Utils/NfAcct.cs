using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;
using System.Xml.Linq;
using SystemInteract;

namespace IPTables.Net.Netfilter.Utils
{
    public class NfAcct
    {
        private ISystemFactory _system;

        public NfAcct(ISystemFactory system)
        {
            _system = system;
        }

        private NfAcctUsage FromXml(String output, String name)
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
                         select new NfAcctUsage(node.Descendants("name").First().Value, ulong.Parse(node.Descendants("pkts").First().Value), ulong.Parse(node.Descendants("bytes").First().Value));

            return usages.FirstOrDefault();
        }

        public NfAcctUsage Get(String name, bool reset = false)
        {
            String cmd = "get {0} xml";
            if (reset)
            {
                cmd += " reset";
            }

            String output, error;
            using (var process = _system.StartProcess("/usr/sbin/nfacct", String.Format(cmd, name)))
            {
                ProcessHelper.ReadToEnd(process, out output, out error);
            }

            if (output.Trim().Length == 0)
            {
                return null;
            }

            return FromXml(output, name);
        }

        public bool Exist(String name)
        {
            return Get(name) != null;
        }

        public void Add(String name)
        {
            String cmd = "add {0}";
            using (var process = _system.StartProcess("/usr/sbin/nfacct", String.Format(cmd, name)))
            {
                String output, error;
                ProcessHelper.ReadToEnd(process, out output, out error);
            }
        }

        public void Delete(String name)
        {
            String cmd = "del {0}";
            using (var process = _system.StartProcess("/usr/sbin/nfacct", String.Format(cmd, name)))
            {
                String output, error;
                ProcessHelper.ReadToEnd(process, out output, out error);
            }
        }

        public List<NfAcctUsage> List(bool reset = false)
        {
            String cmd = "list xml";
            if (reset)
            {
                cmd += " reset";
            }

            String output, error;
            using (var process = _system.StartProcess("/usr/sbin/nfacct", cmd))
            {
                ProcessHelper.ReadToEnd(process, out output, out error);
            }

            //No XML returned for empty
            if (output.Trim().Length == 0)
            {
                return new List<NfAcctUsage>();
            }

            var doc = XDocument.Parse(output);
            var usages = from node in doc.Descendants("obj")
                         select new NfAcctUsage(node.Descendants("name").First().Value, ulong.Parse(node.Descendants("bytes").First().Value), ulong.Parse(node.Descendants("pkts").First().Value));

            return usages.ToList();
        }
    }
}
